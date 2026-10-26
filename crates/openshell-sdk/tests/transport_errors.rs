// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection failures retain the original channel and TLS causes.

use std::error::Error;
use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use openshell_sdk::{ClientConfig, OpenShellClient, SdkError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[tokio::test]
async fn invalid_tls_response_preserves_the_original_transport_cause() {
    openshell_crypto::tls::ensure_default_provider();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (finished, client_finished) = oneshot::channel();
    let server = async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut record = [0; 5];
        stream.read_exact(&mut record).await.unwrap();
        assert_eq!(record[0], 22, "client must send a TLS handshake record");
        let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
        let mut hello = vec![0; length];
        stream.read_exact(&mut hello).await.unwrap();
        // A plaintext HTTP response cannot be accepted as a TLS server record.
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        // Keep the socket alive until the client rejects the response, avoiding
        // platform-specific refusal timing or a reset racing the written bytes.
        client_finished.await.unwrap();
    };
    let client = async move {
        let result =
            OpenShellClient::connect(ClientConfig::new(format!("https://{address}"))).await;
        let _ = finished.send(());
        result
    };
    // Neither future is detached: a deadline drops the listener and peer socket.
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client, server)
    })
    .await
    .expect("the local invalid TLS response must finish within the test deadline");
    let Err(error) = result else {
        panic!("plaintext HTTP must not complete a TLS handshake");
    };

    assert!(matches!(error, SdkError::Connect { .. }));
    assert_eq!(error.code(), "connect");
    let source = error.source().expect("SDK must retain its channel error");
    let mut cause = Some(source);
    let mut invalid_tls = false;
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            invalid_tls |= error.get_ref().is_some_and(|error| {
                matches!(
                    error.downcast_ref::<rustls::Error>(),
                    Some(rustls::Error::InvalidMessage(_))
                )
            });
        }
        cause = error.source();
    }
    assert!(
        invalid_tls,
        "the original TLS cause must remain discoverable"
    );
}
