use chrono::{DateTime, Utc};
use clap::Parser;
use rustls::pki_types::ServerName;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about = "Monitors SSL certificates from a list of URLs")]
struct Args {
    #[arg(short, long, default_value = "urls.txt")]
    urls: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    let file = File::open(&args.urls).map_err(|e| {
        format!("Failed to open '{}': {}. Make sure the file exists.", args.urls, e)
    })?;
    
    let reader = BufReader::new(file);
    let mut handles = vec![];

    println!("{:<25} | {:<20} | {:<10}", "Domain", "Expires At", "Status");
    println!("{}", "-".repeat(70));

    for line in reader.lines() {
        let domain = line?.trim().to_string();
        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }

        handles.push(tokio::spawn(async move {
            let result = timeout(Duration::from_secs(10), check_ssl_expiry(&domain)).await;

            match result {
                Ok(Ok(expiry)) => {
                    let now = Utc::now();
                    let status = if expiry < now { "EXPIRED" } else { "VALID" };
                    let days_left = expiry.signed_duration_since(now).num_days();
                    println!("{:<25} | {:<20} | {} ({} days left)", 
                        domain, expiry.format("%Y-%m-%d"), status, days_left);
                }
                Ok(Err(e)) => println!("{:<25} | Error: {}", domain, e),
                Err(_) => println!("{:<25} | Error: Connection timed out", domain),
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
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
