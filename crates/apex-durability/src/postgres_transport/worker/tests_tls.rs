use super::*;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA_PEM.as_bytes()).unwrap())
        .unwrap();
    roots
}

struct TlsPeer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TlsPeer {
    fn new(stall_handshake: bool) -> Self {
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(SERVER_PEM.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes()).unwrap(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = thread::spawn(move || {
            let mut socket = loop {
                if stopping.load(Ordering::Relaxed) {
                    return;
                }
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("TLS fixture accept failed: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            if stall_handshake {
                let mut bytes = [0; 4096];
                let mut hello_seen = false;
                while !stopping.load(Ordering::Relaxed) {
                    match socket.read(&mut bytes) {
                        Ok(0) => return,
                        Ok(_) if !hello_seen => {
                            assert_eq!(
                                bytes[0], 22,
                                "the stalled peer must receive a TLS handshake"
                            );
                            hello_seen = true;
                        }
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => return,
                    }
                }
                return;
            }
            let server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
            let mut tls = rustls::StreamOwned::new(server, socket);
            let mut bytes = [0; 4096];
            let mut startup = Vec::new();
            let mut ready = false;
            while !stopping.load(Ordering::Relaxed) {
                match tls.read(&mut bytes) {
                    Ok(0) => return,
                    Ok(count) if !ready => {
                        startup.extend_from_slice(&bytes[..count]);
                        if startup.len() >= 4 {
                            let length = u32::from_be_bytes(startup[..4].try_into().unwrap());
                            if startup.len() >= usize::try_from(length).unwrap() {
                                tls.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I").unwrap();
                                ready = true;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => return,
                }
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for TlsPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn connect(
    peer: &TlsPeer,
    hostname: &str,
    roots: rustls::RootCertStore,
) -> Result<WorkerPostgresClient, WorkerPostgresError> {
    let text = format!(
        "host={hostname} hostaddr=127.0.0.1 port={} user=deadline sslmode=require sslnegotiation=direct",
        peer.address.port(),
    );
    let (_, mode) = crate::postgres_transport::parse_and_classify(&text, false).unwrap();
    WorkerPostgresClient::connect_config_with_loader(text.parse().unwrap(), mode, None, move || {
        Ok(roots)
    })
}

#[test]
fn verified_tls_accepts_the_configured_ca_and_original_hostname() {
    let peer = TlsPeer::new(false);
    let client = connect(&peer, "localhost", roots()).unwrap();
    assert!(!client.is_closed());
}

#[test]
fn verified_tls_rejects_a_wrong_hostname_even_with_matching_hostaddr() {
    let peer = TlsPeer::new(false);
    let error = connect(&peer, "wrong.invalid", roots()).unwrap_err();
    assert!(matches!(error, WorkerPostgresError::Database(_)));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn verified_tls_rejects_a_certificate_outside_the_configured_roots() {
    let peer = TlsPeer::new(false);
    let error = connect(&peer, "localhost", rustls::RootCertStore::empty()).unwrap_err();
    assert!(matches!(error, WorkerPostgresError::Database(_)));
}

#[test]
fn a_real_tls_handshake_stall_obeys_the_whole_connect_deadline() {
    let peer = TlsPeer::new(true);
    let start = Instant::now();
    let error = connect(&peer, "localhost", roots()).unwrap_err();
    assert!(matches!(error, WorkerPostgresError::Deadline));
    assert!(start.elapsed() >= Duration::from_secs(4));
    assert!(start.elapsed() < TEST_LIMIT);
}

// Published test-only fixtures from tokio-postgres-rustls 0.14.0 tests/support.
// The server key is public fixture material, never a deployment credential.

const CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgIUevsMJsfhFBpmvZl+RHLkMspwjlIwDQYJKoZIhvcNAQEL
BQAwKDEmMCQGA1UEAwwddG9raW8tcG9zdGdyZXMtcnVzdGxzIFRlc3QgQ0EwHhcN
MjUwODMxMDYyNzA1WhcNMzUwODI5MDYyNzA1WjAoMSYwJAYDVQQDDB10b2tpby1w
b3N0Z3Jlcy1ydXN0bHMgVGVzdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBALW2JKpGbL5Dnua1XPQOeJ5lgbwqJKrdYwl+dMQbp/ir7jkd/tiidnKS
RUIu8FBe4RpoMfwdK6LZtcsMjTMgwCRj1kVp2v5rDTyy8a/Exg2zMQUScIimC3vQ
ynXp4DUOLL7sS6divvC8n6ZzwjTc3Ph7k4NcsarmRYOgjh05CcC3KuaipV5pPJdC
p+qxdptwLUBDVGfGxQI0PFRfpEOFFfn6Rlbxt++WeR9V48oRORJRRrWgEUmKHXmk
m6QwVy3XqxMWSjYufnOUOhwvzkqXHGpafVFahJL9BlO2CdarcquAIm178yJjauF9
jGXEKteLhfM6jjQ35fFKGCoswNrx4EkEQDem5To7Dlt24br8mhcv8GNFOdnzCXw+
MOBe6AbANDePqrnShAdHkiYs/s4JzUtgzH1A0GnmIEfBjH382bsdwS2otxnbfkbY
3HNqmu273NV9QU9XWPZ9iQ75lVVrEo9kWTqh48ncEi7H83WCVNnzLQwYNVH9Qbx/
tRlVLo3YuZ0Dp3nGiNLf2Y7uSA5ZBqH8SLH63+rEcAAl1/ODyykSkwIe/XFMvvmG
KiZpSQrOIYgROZWOsLKFH/1jVqsnXFEcuIh8Dz2y03pn3neXnaACQLVHA/M9MwjB
wzgtroyKEulHUipgpeGzeWG0MfbQy3PhmxO/IXk39orhFrs9VpPJAgMBAAGjYzBh
MB0GA1UdDgQWBBQChDTcpf5T0sdoqlE04yBW6x3eAjAfBgNVHSMEGDAWgBQChDTc
pf5T0sdoqlE04yBW6x3eAjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
BjANBgkqhkiG9w0BAQsFAAOCAgEAX/UJcLwp9U5D6oxYzKoQCZFM63Dmb3yTSqwj
/LX1AZZ807jd/NLy8ozz8hWX5nlLMDtfXQW7vqPb1BXw38bWTymlsc74r9uLxMxb
omD90T/LsKBf1JlMkNgmVLKrCkK/h53oqfjRBgmU2XTsty6957FvYdM+NihzrpZH
yWjxrZ3Ks/BYRh/FBwNUNvBLUFucDl3ozSN1pmEqw37tG/+IO7xBjRCDNlrbgc0g
Ac8Sy4OG/mgM6g8BZeJETCWakWK1B0ENGfCf8W3RijY4Azzn79w3E3sclZsJES2Z
+KhIXOx3HdXEd+zmZbttjZrPgLGNf4gAExL6nrGqgQuXRiFK47lNFN4ENwi3Ftf+
W6sEUpof/D2CZOgm8Y8nAlVvWwo1KIT0WbbKffks9H5h7L3JmUUpy18e4w5YM4jl
Al9QJaj2MSUKba7oGhv/bz5A2bXv/v2XLGNZT2/6H1+NGp+W97ykR8ZMLybWbwPw
LiJEe1OiVi3Usj/3JafO5TU5RSiCqJDzfAzv+e1Yfo0utM2fozgkSPYtZzL9/Q7l
CdkdhZisoq3M5iAWE0LeUK1hOBWCYFFUXIsedKvsX0zJhryogWiD+e/Guo+hmWSC
5dwj7qYnmAmjD+lorqzGztAcx4UHZ82ANc1RfWfWV7JdqZeU+gHTHzYxJtBux3Ch
i6sUXKc=
-----END CERTIFICATE-----"#;

const SERVER_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIEVzCCAj+gAwIBAgIUBUXHF9U2gSfTKnUQIVPFKoucCEcwDQYJKoZIhvcNAQEL
BQAwKDEmMCQGA1UEAwwddG9raW8tcG9zdGdyZXMtcnVzdGxzIFRlc3QgQ0EwHhcN
MjUwODMxMDYyOTIxWhcNMzUwODI5MDYyOTIxWjAUMRIwEAYDVQQDDAlsb2NhbGhv
c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCBvh7v41L8QC/NV8ku
YwU6KW2qov8bPbrmNaBR1FAKvrfWsKxb7hAABV2lb/hWUVPdXiaBkTk+SdVzfTAb
zSnAhH8DYjq1wcgqZs1f8ZFnQjyQeXGep8Rz8ai6N+G+Rc+Fr7Nak/XyYmOjE+20
oztYt5aYJJbYbNC6QiARmhtJBL4mIEnoeztqPT0A10oTZ/Ive77++kY2RiLA/Ixc
LPFdSYgUsxS47xHlV2UibFqCDIBKhf25hX0NwDNOhVLQcuE0XoodIh0AETyyD7zW
FTwBICfds9XryFS6HNHXWgm6lZfWx1bWgw9DlKaSX4ERf7xJPI7m7N+jctEN4j+X
UjddAgMBAAGjgYwwgYkwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwEwYDVR0lBAww
CgYIKwYBBQUHAwEwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMB0GA1UdDgQW
BBTjkxY8SOkPy/sMImjLMGz7Til/4jAfBgNVHSMEGDAWgBQChDTcpf5T0sdoqlE0
4yBW6x3eAjANBgkqhkiG9w0BAQsFAAOCAgEArkKyeGG1AEhc18jcoBzW2ecRvWuq
dCsCfCJvdQz2kQk9yQL7RZzvXDKbKBnn7PJuNGt4eZOm7RHe8lM8ERkapIduP02O
tsXHOabZGYj8TMp+IbqVq4Y49ZvCG63/RZ7RXmNhR6j+fEdsJAJpdsI5WhF6Qc64
5BNyqXIsA2c14htnh7XIlIfKh5jICz/N21BwnIsHSdThE7mv46l1i+cl394X7UiL
XAXvLzpMFvvJXFRNfFdjgZkAfQtF2W4g7jdEwBiIuBeELo8S4HF0xw1aTPgqHlTr
pwwXqOq8Mlu+1ZyGKgh8WqmzQwVRBXg/56EHDt/QAmotILi62Qd9EDlJQoCktRHS
bXWcN5gWNHgQo+wQZHA7yxucKYSdiqgLseGArruf2XX7HC6GtkX2LerCa1r0p8bO
kYmdD1Xa8+bekZkDGO9G23X9OrmpPYO1gSIn/6AMu1pgJSAYxHN6aT9myiYYPpP7
LF1XLJ3iCOBfUJwVcLLAEXdH87R0ym8+3aA7wA4P/eWR7rs62uOZHvNI7Ksu0qIk
aGkHdPsj72KOkWWxbXnOAg65tttNENz505iOQvhVbHjwLgjKtdAtn9xChKA5PVkl
ILTOHlqu+FhipBPVs0UZ5f5ZQt1VagW9yNjfiSC4tONmI4LcXsauu3IPvH4oDiq5
ySXBsVOvE0O8+2Q=
-----END CERTIFICATE-----"#;

const SERVER_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCBvh7v41L8QC/N
V8kuYwU6KW2qov8bPbrmNaBR1FAKvrfWsKxb7hAABV2lb/hWUVPdXiaBkTk+SdVz
fTAbzSnAhH8DYjq1wcgqZs1f8ZFnQjyQeXGep8Rz8ai6N+G+Rc+Fr7Nak/XyYmOj
E+20oztYt5aYJJbYbNC6QiARmhtJBL4mIEnoeztqPT0A10oTZ/Ive77++kY2RiLA
/IxcLPFdSYgUsxS47xHlV2UibFqCDIBKhf25hX0NwDNOhVLQcuE0XoodIh0AETyy
D7zWFTwBICfds9XryFS6HNHXWgm6lZfWx1bWgw9DlKaSX4ERf7xJPI7m7N+jctEN
4j+XUjddAgMBAAECggEACzh0jNLloJAyh3lB77jmQP9H5JEqgTdyUaot88sUowvs
cpeenb1gdTKsRHxYXKq1lzhRxInZNVmwU/Jt4Ib6nJOON9jdHU6lhNlAML3VETo+
v6XpHXYCkkkXilypMXSbJm4paOTRSUWYurKkr6cgS6NmVZZwf0Yl5RMxRSRv8KgQ
qJZ833RzccKuBaehsJNXb1IXJD8pADeVo1KJ5OLCqMnzB2zcbeebOfKKk//aXIO/
9q4Aw52fMsm9TecwGgLaV92TtpAe0uS5UT8C0A66lpwNnksBnq3wBr+xWpZLBBvr
eQGVRkGuiEhPBWqu1cb8kY/PkZ1ltxunzTWDbCr7NwKBgQC2P17DQnMLXoN+qzWf
TZ8fQ2N1w+KEWlsRI0m6/mzkUP2cXRlP0JPfcsXk008M8XhZ5Ow3ceeDJT/HiBvI
Brst4eUgGtJTpA+vIy0egpKjxk1AN8QBMvEUt00MJxRYcK0rKPg/86Xo/Ut3yaZ7
ki5xwT3oUl5LQMSsU7xfCShiWwKBgQC2P06fWZ35XnGRkuLlP0hiEJLhBcB15Lbm
VcMF6BUueDIvB4tDE+F3MnLxyD2p/YRT0M51AOuqI7f3BN0f7bH+T/iZ7r8qmJ5G
BbCu+YkGPeGcjqPXU2hmh7iekZUAXaQuRrwk5xyPBsAYHXJ3bQC2W68D3IRupecB
Z65Z8u+KpwKBgC4nTENcz6/AZsKsby8BxFtxgH2xdusXytpDOofdqQwFKsTvmtpo
sxoygcVacjmP6W+yltPPx9ahl05bvNViRwLuo00HHd7KvKIY4XNJlANf0+6AcOXw
1bbuWNfMCc3/8wrsHDpt5MVlaDhU3BGNSq/KRXhRa8nZBDW0Gw9iTVTjAoGAYKdA
hkhb/LW223KgPN6L/940V3zabmvnCE9xh79nBGcgjkqc8+0mRTYPOeVttqrKND1o
USs00N3yoeIFd/pyzKITAWhaIDgisJYx9wpGPnYxIfuQLxGAK+hM5GPnNvNysEw5
WgTr43q8A84SN/4qQ4xqTEz2O0xnMBqRoAi0O78CgYEAlPz2EbEikMQqVik8OEFf
M1xg9uGV/6OqU+GCTkXxd57Spwmp+7/yeD/AxGCvmnWmIjoeljZu/6K3FDR8Fq2s
VbnFChvKYs1EHqcPX2+D8c44eG93ifFtHmVMeA2qfa+gCWLb0TM1m9+jfxn2S0CH
IOrU3mlx9ZRJl/nm6XCYdXk=
-----END PRIVATE KEY-----"#;
