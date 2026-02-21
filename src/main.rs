use axum::{
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use askama::Template;
use chrono::{DateTime, Utc};
use clap::Parser;
use std::sync::Arc;
use tokio::time::timeout;
use std::time::Duration;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about = "Web-based SSL Certificate Monitor")]
struct Args {
    #[arg(short, long, default_value = "urls.txt")]
    urls: String,
    
    #[arg(short, long, default_value = "3000")]
    port: u16,
}

#[derive(Template)]
#[template(path = "index.html")]
struct DashboardTemplate {
    sites: Vec<SiteResult>,
    last_updated: String,
}

impl IntoResponse for DashboardTemplate {
    fn into_response(self) -> axum::response::Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {err}"),
            )
                .into_response(),
        }
    }
}

struct SiteResult {
    domain: String,
    status: String,
    expiry: String,
    days_left: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arc::new(Args::parse());
    let addr = format!("127.0.0.1:{}", args.port);

    let app = Router::new().route("/", get(move || handler(args.clone())));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("🚀 SSL Dashboard live at http://{}", addr);
    
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handler(args: Arc<Args>) -> impl IntoResponse {
    let mut sites = run_checks(&args.urls).await;
    
    // trying to sort by expiry date
    sites.sort_by_key(|s| s.days_left);

    let last_updated = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    DashboardTemplate { sites, last_updated }
}

async fn run_checks(file_path: &str) -> Vec<SiteResult> {
    let mut results = Vec::new();
    let contents = std::fs::read_to_string(file_path).unwrap_or_default();
    let mut handles = vec![];

    for domain in contents.lines() {
        let domain = domain.trim().to_string();
        if domain.is_empty() || domain.starts_with('#') { continue; }

        handles.push(tokio::spawn(async move {
            match timeout(Duration::from_secs(5), check_ssl_expiry(&domain)).await {
                Ok(Ok(expiry)) => {
                    let now = Utc::now();
                    let days = expiry.signed_duration_since(now).num_days();
                    SiteResult {
                        domain,
                        status: if days < 7 { "EXPIRED".into() } else { "VALID".into() },
                        expiry: expiry.format("%Y-%m-%d").to_string(),
                        days_left: days,
                    }
                }
                _ => SiteResult {
                    domain,
                    status: "ERROR".into(),
                    expiry: "N/A".into(),
                    days_left: 9999,
                },
            }
        }));
    }

    for h in handles {
        if let Ok(res) = h.await { results.push(res); }
    }
    results
}

async fn check_ssl_expiry(domain: &str) -> Result<DateTime<Utc>, Box<dyn std::error::Error + Send + Sync>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(domain.to_string())?.to_owned();

    let addr = format!("{}:443", domain);
    let stream = TcpStream::connect(addr).await?;
    let tls_stream = connector.connect(server_name, stream).await?;
    
    let (_, session) = tls_stream.get_ref();
    let cert_chain = session.peer_certificates().ok_or("No certificate found")?;
    
    let cert_der = &cert_chain[0];
    let (_, parsed_cert) = parse_x509_certificate(cert_der)?;
    
    let expiry_ts = parsed_cert.validity().not_after.timestamp();
    Ok(DateTime::from_timestamp(expiry_ts, 0).unwrap_or_default())
}
