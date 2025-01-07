use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use rcgen::SanType;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::net::Ipv4Addr;
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    time::interval,
};
use tokio_rustls::TlsAcceptor;

// TODO: You're not *really* supposed to use rustls_cert_gen as a lib, it's a bin.
// I should take the bits I need out of `rcgen` directly instead
use rustls_cert_gen::{Ca, CertificateBuilder};

#[tokio::main]
async fn main() {
    // TODO: probably check if the cert exists before recreating it
    let ca = CertificateBuilder::new()
        .certificate_authority()
        .organization_name("OneVariable GmbH")
        .build()
        .unwrap();

    // We DO want to write the ca-cert to a path, because the client
    // will need to get the `ca-cert.pem` to verify the ephemeral leaf
    // certificates we create
    ca.serialize_pem()
        .write(&PathBuf::from("../certs"), "ca-cert")
        .unwrap();

    tokio::task::spawn(server(ca)).await.unwrap();
}

async fn server(ca: Ca) {
    let addr = "0.0.0.0:9009";

    // Get the initial set of IP addresses
    let mut addrs = get_local_ips().into_iter().collect::<HashSet<_>>();
    loop {
        println!("IP Addresses:");
        for addr in addrs.iter() {
            println!("* {addr:?}");
        }
        let sans = addrs
            .iter()
            .cloned()
            .map(SanType::IpAddress)
            .collect::<Vec<_>>();

        // Create a new ephemeral (in memory only) certificate to use. It has
        // SANs for each of our public IPs.
        let entity_pem = CertificateBuilder::new()
            .end_entity()
            .common_name("Poststation API Server")
            .subject_alternative_names(sans)
            .build(&ca)
            .unwrap()
            .serialize_pem();

        let cert = CertificateDer::from_pem_slice(entity_pem.cert_pem.as_bytes()).unwrap();
        let key = PrivateKeyDer::from_pem_slice(entity_pem.private_key_pem.as_bytes()).unwrap();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();

        // Create a new TLS/TCP acceptor using our ephemeral cert
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await.unwrap();

        println!("Listening...");
        let listen_fut = async {
            loop {
                // Spawn an echoer task for each connection
                //
                // These tasks WILL outlive a change in IPs, but that's fine I suppose,
                // if their interface closed, the connection would drop anyway.
                let (stream, peer_addr) = listener.accept().await.unwrap();
                tokio::task::spawn(echoer(stream, peer_addr, acceptor.clone()));
            }
        };

        // Listen until our set of IP addresses change, then regenerate the
        // cert with the new list of SANs
        select! {
            new_addrs = wait_ip_change(&addrs, Duration::from_secs(1)) => {
                println!("IP addr change!");
                addrs = new_addrs;
            }
            _ = listen_fut => {
                println!("Done I guess?");
                break;
            }
        }
    }
}

async fn echoer(stream: TcpStream, peer_addr: SocketAddr, acceptor: TlsAcceptor) {
    println!("Opened conn to {peer_addr:?}");
    let stream = acceptor.accept(stream).await.unwrap();
    let mut buf = [0u8; 1024];
    let (mut reader, mut writer) = split(stream);
    while let Ok(n) = reader.read(&mut buf).await {
        writer.write_all(&buf[..n]).await.unwrap();
        writer.flush().await.unwrap();
    }
}

async fn wait_ip_change(current: &HashSet<IpAddr>, ival: Duration) -> HashSet<IpAddr> {
    let mut ticker = interval(ival);
    loop {
        ticker.tick().await;
        let new_set = get_local_ips().into_iter().collect::<HashSet<_>>();
        if &new_set != current {
            return new_set;
        }
    }
}

fn get_local_ips() -> Vec<IpAddr> {
    let Ok(addrs) = local_ip_address::list_afinet_netifas() else {
        // If we can't get network interfaces, default to localhosts
        println!("Error getting network interfaces!");
        return vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
    };
    addrs
        .into_iter()
        .filter_map(|(_name, addr)| {
            match addr {
                v4 @ IpAddr::V4(_) => Some(v4),
                IpAddr::V6(ipv6_addr) => {
                    // Filter out link-local addresses
                    //
                    // basically `IpAddrV6::is_unicast_link_local`, which isn't stable
                    if ipv6_addr.segments()[0] & 0xffc0 == 0xfe80 {
                        None
                    } else {
                        Some(IpAddr::V6(ipv6_addr))
                    }
                }
            }
        })
        .collect()
}
