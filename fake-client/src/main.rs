use std::{sync::Arc, time::Duration};

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    RootCertStore,
};
use tokio::{io::{split, AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::sleep};
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store
        .add(CertificateDer::from_pem_file("../certs/ca-cert.pem").unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect("127.0.0.1:9009").await.unwrap();
    let stream = connector
        .connect(
            ServerName::IpAddress("127.0.0.1".try_into().unwrap()),
            stream,
        )
        .await
        .unwrap();
    let (mut reader, mut writer) = split(stream);

    let mut buf = [0u8; 1024];
    for i in 0..5 {
        let message = format!("Test message number {i}");
        println!("-> Tx: '{message}'");
        writer.write_all(message.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(message.as_bytes(), &buf[..n]);
        println!("<- Rx: '{message}'");
        sleep(Duration::from_secs(1)).await;
    }
    println!("Done!");
}
