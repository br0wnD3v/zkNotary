use actix_web::{ web, HttpResponse, Responder };
use eyre::Result;
use http_body_util::{ BodyExt as _, Empty };
use hyper::{ body::Bytes, Request, StatusCode };
use hyper_util::rt::TokioIo;
use serde::{ Deserialize, Serialize };
use std::{ env, ops::Range };
use tlsn_core::proof::TlsProof;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{ FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt };
use tracing::debug;

use tlsn_prover::tls::{ Prover, ProverConfig };

use crate::setup_notary_connection;

// Setting of the application server
// const SERVER_DOMAIN: &str = "api.binance.com";
// const ROUTE: &str = "api/v3/ticker/price";

// Configuration of notarization
const NOTARY_MAX_TRANSCRIPT_SIZE: usize = 16384;

// Setting of the notary server
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;

/// Response object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
    pub session_id: String,
}

/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
    pub client_type: ClientType,
    /// Maximum transcript size in bytes
    pub max_transcript_size: Option<usize>,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    /// Client that has access to the transport layer
    Tcp,
    /// Client that cannot directly access transport layer, e.g. browser extension
    Websocket,
}

#[derive(serde::Deserialize)]
pub struct QueryParams {
    server_domain: String,
    route: String,
    sub_params: String,
}

// pub async fn notarize(server_domain: String, route: String, params: String) -> impl Responder {
pub async fn notarize(query_params: web::Query<QueryParams>) -> impl Responder {
    let server_domain = &query_params.server_domain;
    let server_route = &query_params.route;
    let server_params = &query_params.sub_params;

    let provider = extract_provider(&server_domain).unwrap_or_else(|_|
        "default_provider".to_string()
    );

    dotenv::dotenv().ok();
    let bearer_token;

    println!("{} {} {} {}", server_domain, server_route, server_params, provider);

    match provider.as_str() {
        "coinmarketcap" => {
            bearer_token = env::var("X-CMC_PRO_API_KEY").unwrap();
        }
        "coinapi" => {
            bearer_token = env::var("X-CoinAPI-Key").unwrap();
        }
        "coinranking" => {
            bearer_token = env::var("x-access-token").unwrap();
        }
        "swapzone" => {
            bearer_token = env::var("x-api-key").unwrap();
        }
        _ => {
            bearer_token = String::from("NaN");
        }
    }

    let (notary_tls_socket, session_id) = setup_notary_connection(
        NOTARY_HOST,
        NOTARY_PORT,
        Some(NOTARY_MAX_TRANSCRIPT_SIZE)
    ).await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(server_domain.clone())
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config).setup(notary_tls_socket.compat()).await.unwrap();

    let client_socket = tokio::net::TcpStream::connect((server_domain.clone(), 443)).await.unwrap();

    println!("Connected to the Notary");

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1
        ::handshake(TokioIo::new(tls_connection.compat())).await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to fetch the tweet
    let request = Request::builder()
        .uri(format!("https://{}/{}?{}", server_domain, server_route, server_params))
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("Authorization", format!("Bearer {}", bearer_token))
        .body(Empty::<Bytes>::new())
        .unwrap();

    debug!("Sending request");
    println!("Starting an MPC TLS connection with {}'s server", provider);

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK);

    debug!("Request OK");
    println!("Got a response from the {}'s server", provider);

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed = serde_json
        ::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload))
        .unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // Close the connection to the server
    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();
    client_socket.shutdown().await.unwrap();
    print!("Closed the connection to the {}'s server", provider);

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization
    let mut prover = prover.start_notarize();

    // Identify the ranges in the transcript that contain secrets
    let (public_ranges, private_ranges) = find_ranges(
        prover.sent_transcript().data(),
        &[bearer_token.as_bytes()]
    );

    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    // Collect commitment ids for the outbound transcript
    let mut commitment_ids = public_ranges
        .iter()
        .chain(private_ranges.iter())
        .map(|range| builder.commit_sent(range).unwrap())
        .collect::<Vec<_>>();

    // Commit to the full received transcript in one shot, as we don't need to redact anything
    commitment_ids.push(builder.commit_recv(&(0..recv_len)).unwrap());

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");
    println!("Notarization completed successfully!");

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal everything but the bearer token (which was assigned commitment id 2)
    proof_builder.reveal_by_id(commitment_ids[0]).unwrap();
    proof_builder.reveal_by_id(commitment_ids[1]).unwrap();
    proof_builder.reveal_by_id(commitment_ids[3]).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    let res =
        serde_json::json!({
      "proof": proof,
      "notarized_session": notarized_session
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .body(serde_json::to_string_pretty(&res).unwrap())
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], sub_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in sub_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..idx + w.len());
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }
    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}

fn find_provider<'a>(original: &'a str, providers: &'a [&'a str]) -> Option<&'a str> {
    for provider in providers.iter() {
        if original.contains(provider) {
            return Some(provider);
        }
    }
    None
}

fn extract_provider(sent_server: &str) -> Result<String> {
    let providers = [
        "binance",
        "cryptocompare",
        "coinmarketcap",
        "coinpaprika",
        "messari",
        "coincap",
        "coinlore",
        "coincodex",
        "coingecko",
        "kucoin",
        "huobi",
        "bybit",
        "cex.io",
        "swapzone",
    ];

    match find_provider(sent_server, &providers) {
        Some(provider) => Ok(provider.to_string()),
        None => Ok("".to_string()),
    }
}
