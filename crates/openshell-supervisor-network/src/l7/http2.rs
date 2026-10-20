// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP/2 transport for REST method/path policies, including opaque gRPC bodies.
//! Credential resolution uses the same request-scoped ownership and generation
//! checks as HTTP/1. Body transforms and middleware are deliberately not admitted
//! by the caller until their HTTP/2 semantics are implemented.

use std::sync::Arc;

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::secrets;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinSet;

use super::provider::{L7Provider, L7Request};
use super::relay::{L7EvalContext, evaluate_l7_request, prepare_inspected_request};
use super::{L7EndpointConfig, L7RequestInfo};
use crate::opa::{PolicyGenerationGuard, TunnelPolicyEngine};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_STREAMS: u32 = 32;
const MAX_GRPC_MESSAGE: usize = 16 * 1024 * 1024;

enum BodyGuard<'a> {
    Stream(secrets::body::BodyPlaceholderGuard<'a>),
    Grpc {
        pending: Vec<u8>,
        classifier: Option<&'a secrets::body::BodyCredentialClassifier>,
    },
}

impl<'a> BodyGuard<'a> {
    fn new(classifier: Option<&'a secrets::body::BodyCredentialClassifier>, grpc: bool) -> Self {
        if grpc {
            Self::Grpc {
                pending: Vec::new(),
                classifier,
            }
        } else {
            Self::Stream(secrets::body::BodyPlaceholderGuard::new(classifier))
        }
    }

    fn push(&mut self, data: &[u8]) -> Result<Bytes> {
        match self {
            Self::Stream(scanner) => Ok(Bytes::from(scanner.push(data)?)),
            Self::Grpc {
                pending,
                classifier,
            } => {
                pending.extend_from_slice(data);
                let mut safe = Vec::new();
                let mut offset = 0;
                while pending.len() - offset >= 5 {
                    let frame = &pending[offset..];
                    if frame[0] != 0 {
                        return Err(miette!(
                            "compressed gRPC request credential inspection is unsupported"
                        ));
                    }
                    let length = usize::try_from(u32::from_be_bytes(
                        frame[1..5].try_into().expect("fixed frame header"),
                    ))
                    .into_diagnostic()?;
                    if length > MAX_GRPC_MESSAGE {
                        return Err(miette!(
                            "gRPC request message exceeds credential inspection limit"
                        ));
                    }
                    if frame.len() < length + 5 {
                        break;
                    }
                    // Each protobuf message is an independent application value.
                    // Finish its scan before forwarding, without waiting for the
                    // end of a bidirectional RPC stream.
                    let mut scanner = secrets::body::BodyPlaceholderGuard::new(*classifier);
                    let first = scanner.push(&frame[5..length + 5])?;
                    let last = scanner.finish()?;
                    safe.extend_from_slice(&frame[..5]);
                    safe.extend(first);
                    safe.extend(last);
                    offset += length + 5;
                }
                pending.drain(..offset);
                Ok(Bytes::from(safe))
            }
        }
    }

    fn finish(self) -> Result<Bytes> {
        match self {
            Self::Stream(scanner) => Ok(Bytes::from(scanner.finish()?)),
            Self::Grpc { pending, .. } if pending.is_empty() => Ok(Bytes::new()),
            Self::Grpc { .. } => Err(miette!("truncated gRPC request message")),
        }
    }
}

/// Parse HTTP/2 headers through the existing bounded HTTP authority/path parser.
async fn inspected_request(request: &Request<RecvStream>) -> Result<L7Request> {
    let authority = request
        .uri()
        .authority()
        .ok_or_else(|| miette!("missing HTTP/2 authority"))?;
    if request.uri().scheme_str() != Some("https") {
        return Err(miette!("HTTP/2 inspected TLS request requires https"));
    }
    let target = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    if secrets::contains_reserved_credential_marker(target) {
        return Err(miette!(
            "HTTP/2 credential placeholders are restricted to headers"
        ));
    }
    let mut raw = format!(
        "{} {target} HTTP/1.1\r\nHost: {authority}\r\n",
        request.method()
    )
    .into_bytes();
    for (name, value) in request.headers() {
        if name == "host"
            || matches!(
                name.as_str(),
                "connection" | "transfer-encoding" | "upgrade" | "proxy-authorization"
            )
        {
            return Err(miette!("unsupported HTTP/2 header"));
        }
        raw.extend_from_slice(name.as_str().as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
        if raw.len() > MAX_HEADERS {
            return Err(miette!("HTTP/2 headers exceed limit"));
        }
    }
    raw.extend_from_slice(b"\r\n");
    let (mut writer, mut reader) = tokio::io::duplex(MAX_HEADERS + 4);
    writer.write_all(&raw).await.into_diagnostic()?;
    drop(writer);
    super::rest::RestProvider::default()
        .parse_request(&mut reader)
        .await?
        .ok_or_else(|| miette!("missing HTTP/2 request headers"))
}

fn resolved_headers(raw: &[u8], resolver: Option<&secrets::SecretResolver>) -> Result<HeaderMap> {
    let rewritten = secrets::rewrite_http_header_block(raw, resolver).into_diagnostic()?;
    let text = std::str::from_utf8(&rewritten.rewritten).into_diagnostic()?;
    let mut headers = HeaderMap::new();
    for line in text
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
    {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| miette!("invalid rewritten header"))?;
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        let name = HeaderName::from_bytes(name.as_bytes()).into_diagnostic()?;
        let mut value = HeaderValue::from_str(value.trim_start()).into_diagnostic()?;
        value.set_sensitive(true);
        headers.append(name, value);
    }
    Ok(headers)
}

async fn pump(
    mut source: RecvStream,
    mut destination: SendStream<Bytes>,
    guard: PolicyGenerationGuard,
    request_context: Option<&L7EvalContext>,
    inspect_body: bool,
    grpc: bool,
) -> Result<()> {
    let mut scanner = inspect_body.then(|| {
        BodyGuard::new(
            request_context.and_then(|ctx| ctx.body_classifier.as_deref()),
            grpc,
        )
    });
    loop {
        let data = tokio::select! {
            data = source.data() => data,
            _ = std::future::poll_fn(|cx| destination.poll_reset(cx)) => {
                return Err(miette!("HTTP/2 receiving peer cancelled the stream"));
            }
        };
        let Some(data) = data else {
            break;
        };
        guard.ensure_current()?;
        let data = data.into_diagnostic()?;
        let length = data.len();
        let data = if let Some(scanner) = &mut scanner {
            scanner.push(&data)?
        } else {
            data
        };
        send_data(&mut destination, data, &guard, request_context).await?;
        source
            .flow_control()
            .release_capacity(length)
            .into_diagnostic()?;
    }
    if let Some(scanner) = scanner {
        send_data(&mut destination, scanner.finish()?, &guard, request_context).await?;
    }
    guard.ensure_current()?;
    let trailers = tokio::select! {
        trailers = source.trailers() => trailers.into_diagnostic()?,
        _ = std::future::poll_fn(|cx| destination.poll_reset(cx)) => {
            return Err(miette!("HTTP/2 receiving peer cancelled the stream"));
        }
    };
    if let Some(trailers) = trailers {
        if request_context.is_some()
            && trailers.iter().any(|(name, value)| {
                secrets::contains_reserved_credential_marker(name.as_str())
                    || secrets::contains_reserved_credential_marker_bytes(value.as_bytes())
            })
        {
            return Err(miette!(
                "HTTP/2 credential placeholders in trailers are unsupported"
            ));
        }
        destination.send_trailers(trailers).into_diagnostic()?;
    } else {
        destination
            .send_data(Bytes::new(), true)
            .into_diagnostic()?;
    }
    Ok(())
}

async fn send_data(
    destination: &mut SendStream<Bytes>,
    mut data: Bytes,
    guard: &PolicyGenerationGuard,
    context: Option<&L7EvalContext>,
) -> Result<()> {
    while !data.is_empty() {
        destination.reserve_capacity(data.len().min(16 * 1024));
        let capacity = std::future::poll_fn(|cx| destination.poll_capacity(cx))
            .await
            .ok_or_else(|| miette!("HTTP/2 stream closed"))?
            .into_diagnostic()?;
        guard.ensure_current()?;
        if let Some(guard) = context.and_then(super::relay::credential_generation_guard) {
            guard.ensure_current()?;
        }
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        destination.send_data(chunk, false).into_diagnostic()?;
    }
    Ok(())
}

async fn exchange(
    request: Request<RecvStream>,
    mut downstream: h2::server::SendResponse<Bytes>,
    upstream: h2::client::SendRequest<Bytes>,
    config: Arc<L7EndpointConfig>,
    engine: Arc<TunnelPolicyEngine>,
    context: Arc<L7EvalContext>,
) -> Result<()> {
    let request_headers = inspected_request(&request).await?;
    if !super::relay::request_authority_matches_endpoint(&request_headers, &context) {
        return Err(miette!(
            "HTTP/2 authority differs from authorized destination"
        ));
    }
    let info = L7RequestInfo {
        action: request_headers.action.clone(),
        target: request_headers.target.clone(),
        query_params: request_headers.query_params.clone(),
        graphql: None,
        jsonrpc: None,
    };
    let (allowed, reason) = evaluate_l7_request(&engine, &context, &info)?;
    super::relay::emit_l7_request_log(
        &context,
        &info.action,
        &info.target,
        if allowed { "allow" } else { "deny" },
        "rest",
        &reason,
        Some("HTTP/2"),
    );
    if !allowed {
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(())
            .into_diagnostic()?;
        downstream.send_response(response, true).into_diagnostic()?;
        return Ok(());
    }
    let (prepared, scoped) = tokio::select! {
        prepared = prepare_inspected_request(request_headers, &context, &engine, &config, &info) => prepared?,
        _ = std::future::poll_fn(|cx| downstream.poll_reset(cx)) => {
            return Err(miette!("HTTP/2 client cancelled before request admission"));
        }
    };
    let mut upstream = tokio::select! {
        upstream = upstream.ready() => upstream.into_diagnostic()?,
        _ = std::future::poll_fn(|cx| downstream.poll_reset(cx)) => {
            return Err(miette!("HTTP/2 client cancelled before forwarding"));
        }
    };
    let (mut parts, body) = request.into_parts();
    parts.headers = resolved_headers(&prepared.raw_header, scoped.secret_resolver.as_deref())?;
    engine.generation_guard().ensure_current()?;
    if let Some(guard) = super::relay::credential_generation_guard(&scoped) {
        guard.ensure_current()?;
    }
    let end = body.is_end_stream();
    let grpc = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|value| {
                value == "application/grpc" || value.starts_with("application/grpc+")
            })
        });
    let (response, send) = upstream
        .send_request(Request::from_parts(parts, ()), end)
        .into_diagnostic()?;
    let guard = engine.generation_guard().clone();
    let upload = async {
        if !end {
            pump(
                body,
                send,
                guard.clone(),
                Some(&scoped),
                config.deny_uninspected_body_credentials(scoped.secret_resolver.is_some()),
                grpc,
            )
            .await?;
        }
        Ok::<_, miette::Report>(())
    };
    let download = async {
        let response = tokio::select! {
            response = response => response.into_diagnostic()?,
            _ = std::future::poll_fn(|cx| downstream.poll_reset(cx)) => {
                // Cancelling this exchange drops both upstream stream handles.
                // h2 then resets the upstream rather than retaining a stalled RPC.
                return Err(miette!("HTTP/2 client cancelled while awaiting response"));
            }
        };
        let (parts, body) = response.into_parts();
        let end = body.is_end_stream();
        let send = downstream
            .send_response(Response::from_parts(parts, ()), end)
            .into_diagnostic()?;
        if !end {
            pump(body, send, guard.clone(), None, false, false).await?;
        }
        Ok::<_, miette::Report>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

/// Multiplex bounded streams while retaining native policy-generation fencing.
pub async fn relay<C, U>(
    client: C,
    upstream: U,
    config: L7EndpointConfig,
    engine: TunnelPolicyEngine,
    context: L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut downstream = h2::server::Builder::new()
        .max_concurrent_streams(MAX_STREAMS)
        .max_header_list_size(u32::try_from(MAX_HEADERS).expect("fixed header limit fits u32"))
        .handshake(client)
        .await
        .into_diagnostic()?;
    let (sender, connection) = h2::client::handshake(upstream).await.into_diagnostic()?;
    let engine = Arc::new(engine);
    let config = Arc::new(config);
    let context = Arc::new(context);
    let guard = engine.generation_guard().clone();
    let serve = async {
        let mut tasks = JoinSet::new();
        loop {
            let at_capacity = tasks.len() >= MAX_STREAMS as usize;
            if at_capacity {
                tracing::debug!(
                    category = "exchange_backpressure",
                    active_tasks = tasks.len(),
                    limit = MAX_STREAMS,
                    "HTTP/2 relay awaiting exchange capacity"
                );
            }
            tokio::select! {
                request = async {
                    if at_capacity {
                        // Retired wire streams can still have exchange tasks awaiting
                        // cancellation or joining. Let H2 queue compliant replacements
                        // until a task slot opens, while continuing to drive active I/O.
                        std::future::poll_fn(|cx| downstream.poll_closed(cx))
                            .await
                            .map(|()| None)
                    } else {
                        downstream.accept().await.transpose()
                    }
                } => {
                    let Some((request, response)) = request.into_diagnostic()? else { break; };
                    tasks.spawn(exchange(request, response, sender.clone(), config.clone(), engine.clone(), context.clone()));
                }
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            // Only typed transport categories are safe to expose.
                            // The report may contain credential-resolution details.
                            let h2_reason = error.chain()
                                .find_map(|cause| cause.downcast_ref::<h2::Error>())
                                .and_then(h2::Error::reason);
                            let io_kind = error.chain()
                                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                                .map(std::io::Error::kind);
                            tracing::debug!(
                                category = "exchange_failure",
                                ?h2_reason,
                                ?io_kind,
                                "HTTP/2 relay exchange ended unsuccessfully"
                            );
                        }
                        Err(_) => return Err(miette!("HTTP/2 relay task failed")),
                    }
                }
            }
        }
        tasks.abort_all();
        Ok::<_, miette::Report>(())
    };
    tokio::select! {
        result = serve => result,
        result = connection => result.into_diagnostic(),
        () = guard.wait_until_stale() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::{NetworkInput, OpaEngine};
    use std::path::PathBuf;
    use std::time::Duration;

    const POLICY: &str = r"
network_policies:
  rpc:
    name: rpc
    endpoints:
      - host: rpc.example.test
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: POST, path: /rpc/read}
    binaries:
      - {path: /usr/bin/client}
";

    #[tokio::test]
    async fn concurrent_stream_rollover_accepts_peer_compliant_replacements() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let engine =
                OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), POLICY)
                    .unwrap();
            let input = NetworkInput {
                host: "rpc.example.test".into(),
                port: 443,
                binary_path: PathBuf::from("/usr/bin/client"),
                binary_sha256: "unused".into(),
                ancestors: vec![],
                cmdline_paths: vec![],
            };
            let (config, generation) = engine
                .query_endpoint_config_with_generation(&input)
                .unwrap();
            let config = super::super::parse_l7_config(&config.unwrap()).unwrap();
            let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
            let context = L7EvalContext {
                host: input.host,
                port: 443,
                request_default_port: Some(443),
                binary_path: "/usr/bin/client".into(),
                policy_name: "rpc".into(),
                ..Default::default()
            };
            let (app, relay_client) = tokio::io::duplex(64 * 1024);
            let (relay_upstream, upstream) = tokio::io::duplex(64 * 1024);
            // Own the real relay future so the peer can retire streams and queue
            // replacements before the relay reaps their exchange tasks. There is
            // no scheduler sleep or test-only production admission hook.
            let relay = relay(relay_client, relay_upstream, config, tunnel, context);
            tokio::pin!(relay);
            let upstream_task = tokio::spawn(async move {
                let mut server = h2::server::handshake(upstream).await.unwrap();
                let mut replies = Vec::new();
                while let Some(request) = server.accept().await {
                    let (request, mut response) = request.unwrap();
                    assert!(request.body().is_end_stream());
                    replies.push(response.send_response(Response::new(()), false).unwrap());
                    assert!(
                        replies.len() <= (MAX_STREAMS + MAX_STREAMS / 2) as usize,
                        "upstream must not receive replayed requests"
                    );
                }
            });
            let (mut app, connection) = h2::client::handshake(app).await.unwrap();
            tokio::pin!(connection);
            let mut sends = Vec::new();
            let mut responses = Vec::new();
            for _ in 0..MAX_STREAMS {
                app = app.ready().await.unwrap();
                let (response, send) = app
                    .send_request(
                        Request::builder()
                            .method("POST")
                            .uri("https://rpc.example.test/rpc/read")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                sends.push(send);
                responses.push(response);
            }
            let initial = tokio::select! {
                result = &mut relay => panic!("relay ended before initial streams: {result:?}"),
                result = &mut connection => panic!("client ended before initial streams: {result:?}"),
                result = futures::future::try_join_all(responses) => result.unwrap(),
            };
            assert_eq!(initial.len(), MAX_STREAMS as usize);
            assert_eq!(connection.max_concurrent_send_streams(), MAX_STREAMS as usize);

            // RST_STREAM closes these streams in the peer's H2 accounting before
            // it opens replacements. Keep the other streams concurrently active.
            let rollover = MAX_STREAMS / 2;
            for send in sends.iter_mut().take(rollover as usize) {
                send.send_reset(h2::Reason::CANCEL);
            }
            // Drive only the peer connection to flush the retirements. The relay
            // future remains unpolled, so its old tasks have not been reaped.
            assert!(futures::poll!(connection.as_mut()).is_pending());
            let mut replacements = Vec::new();
            for _ in 0..rollover {
                app = app.ready().await.unwrap();
                let (response, send) = app
                    .send_request(
                        Request::builder()
                            .method("POST")
                            .uri("https://rpc.example.test/rpc/read")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                sends.push(send);
                replacements.push(response);
            }
            assert!(futures::poll!(connection.as_mut()).is_pending());
            let replaced = tokio::select! {
                result = &mut relay => panic!("relay ended during rollover: {result:?}"),
                result = &mut connection => panic!("client ended during rollover: {result:?}"),
                result = futures::future::try_join_all(replacements) => result
                    .expect("peer-compliant replacements must not be reset"),
            };
            assert_eq!(replaced.len(), rollover as usize);
            upstream_task.abort();
        })
        .await
        .expect("concurrent stream rollover deadline");
    }

    #[tokio::test]
    async fn downstream_cancellation_resets_upstream_and_releases_relay_slots() {
        for response_started in [false, true] {
            let engine =
                OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), POLICY)
                    .unwrap();
            let input = NetworkInput {
                host: "rpc.example.test".into(),
                port: 443,
                binary_path: PathBuf::from("/usr/bin/client"),
                binary_sha256: "unused".into(),
                ancestors: vec![],
                cmdline_paths: vec![],
            };
            let (config, generation) = engine
                .query_endpoint_config_with_generation(&input)
                .unwrap();
            let config = super::super::parse_l7_config(&config.unwrap()).unwrap();
            let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
            let context = L7EvalContext {
                host: input.host,
                port: 443,
                request_default_port: Some(443),
                binary_path: "/usr/bin/client".into(),
                policy_name: "rpc".into(),
                ..Default::default()
            };
            let (app, relay_client) = tokio::io::duplex(8192);
            let (relay_upstream, upstream) = tokio::io::duplex(8192);
            let relay_task =
                tokio::spawn(relay(relay_client, relay_upstream, config, tunnel, context));
            let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel(4);
            let (reset_tx, mut reset_rx) = tokio::sync::mpsc::channel(4);
            let upstream_task = tokio::spawn(async move {
                let mut server = h2::server::handshake(upstream).await.unwrap();
                let mut pending = JoinSet::new();
                while let Some(request) = server.accept().await {
                    let (request, mut response) = request.unwrap();
                    assert!(request.body().is_end_stream(), "upload must have completed");
                    let (seen, reset) = (seen_tx.clone(), reset_tx.clone());
                    pending.spawn(async move {
                        let reason = if response_started {
                            let mut body =
                                response.send_response(Response::new(()), false).unwrap();
                            seen.send(()).await.unwrap();
                            std::future::poll_fn(|cx| body.poll_reset(cx))
                                .await
                                .unwrap()
                        } else {
                            seen.send(()).await.unwrap();
                            std::future::poll_fn(|cx| response.poll_reset(cx))
                                .await
                                .unwrap()
                        };
                        reset.send(reason).await.unwrap();
                    });
                }
            });
            let (mut app, connection) = h2::client::handshake(app).await.unwrap();
            let app_task = tokio::spawn(connection);
            // More cancellations than the relay's slot limit prove that cancelled
            // exchanges do not accumulate even when the connection stays open.
            for _ in 0..=MAX_STREAMS {
                app = app.ready().await.unwrap();
                let (response, mut send) = app
                    .send_request(
                        Request::builder()
                            .method("POST")
                            .uri("https://rpc.example.test/rpc/read")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                tokio::pin!(response);
                tokio::time::timeout(Duration::from_secs(1), seen_rx.recv())
                    .await
                    .expect("relay slot was not released")
                    .unwrap();
                let held_response = if response_started {
                    Some((&mut response).await.unwrap())
                } else {
                    None
                };
                send.send_reset(h2::Reason::CANCEL);
                let reason = tokio::time::timeout(Duration::from_millis(500), reset_rx.recv())
                    .await
                    .expect("downstream cancellation did not reach the stalled upstream")
                    .unwrap();
                assert_eq!(reason, h2::Reason::CANCEL);
                drop(held_response);
            }
            relay_task.abort();
            upstream_task.abort();
            app_task.abort();
        }
    }

    #[tokio::test]
    async fn streams_grpc_and_credentials_with_policy_and_authority_checks() {
        let engine =
            OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), POLICY)
                .unwrap();
        let input = NetworkInput {
            host: "rpc.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/client"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = super::super::parse_l7_config(&config.unwrap()).unwrap();
        let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
        let (environment, resolver) = secrets::SecretResolver::from_provider_env(
            [("TOKEN".into(), "supervisor-only-token".into())].into(),
        );
        let placeholder = environment["TOKEN"].clone();
        let context = L7EvalContext {
            host: input.host,
            port: 443,
            request_default_port: Some(443),
            binary_path: "/usr/bin/client".into(),
            policy_name: "rpc".into(),
            secret_resolver: resolver.map(Arc::new),
            ..Default::default()
        };
        let (app, relay_client) = tokio::io::duplex(8192);
        let (relay_upstream, upstream) = tokio::io::duplex(8192);
        let relay_task = tokio::spawn(relay(relay_client, relay_upstream, config, tunnel, context));
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel(8);
        let upstream_task = tokio::spawn(async move {
            let mut server = h2::server::handshake(upstream).await.unwrap();
            while let Some(request) = server.accept().await {
                let (request, mut response) = request.unwrap();
                let tx = seen_tx.clone();
                tokio::spawn(async move {
                    let (parts, mut body) = request.into_parts();
                    let mut received_body = Vec::new();
                    while let Some(data) = body.data().await {
                        let data = data.unwrap();
                        body.flow_control().release_capacity(data.len()).unwrap();
                        received_body.extend_from_slice(&data);
                        if received_body.len() == 10 {
                            break;
                        }
                    }
                    tx.send((parts, received_body)).await.unwrap();
                    let mut reply = response
                        .send_response(
                            Response::builder()
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    reply
                        .send_data(Bytes::from_static(b"\0\0\0\0\x05hello"), false)
                        .unwrap();
                    let mut trailers = HeaderMap::new();
                    trailers.insert("grpc-status", HeaderValue::from_static("0"));
                    reply.send_trailers(trailers).unwrap();
                    while let Some(data) = body.data().await {
                        let data = data.unwrap();
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                });
            }
        });
        let (mut app, connection) = h2::client::handshake(app).await.unwrap();
        let app_task = tokio::spawn(connection);
        app = app.ready().await.unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("https://rpc.example.test/rpc/read")
            .header("content-type", "application/grpc")
            .header("authorization", format!("Bearer {placeholder}"))
            .body(())
            .unwrap();
        let (response, mut body) = app.send_request(request, false).unwrap();
        let payload = b"\0\0\0\0\x05hello";
        body.send_data(Bytes::copy_from_slice(&payload[..3]), false)
            .unwrap();
        body.send_data(Bytes::copy_from_slice(&payload[3..]), false)
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        // The upstream must answer while the request stream is still open.
        body.send_data(Bytes::new(), true).unwrap();
        let (parts, received_body) = seen_rx.recv().await.unwrap();
        assert_eq!(
            parts.headers["authorization"],
            "Bearer supervisor-only-token"
        );
        assert_eq!(received_body, payload);
        let mut body = response.into_body();
        let mut reply = Vec::new();
        while let Some(data) = body.data().await {
            let data = data.unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            reply.extend_from_slice(&data);
        }
        assert_eq!(reply, payload);
        assert_eq!(body.trailers().await.unwrap().unwrap()["grpc-status"], "0");
        app = app.ready().await.unwrap();
        let (denied, _) = app
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://rpc.example.test/rpc/write")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(denied.await.unwrap().status(), StatusCode::FORBIDDEN);
        app = app.ready().await.unwrap();
        let (mismatch, _) = app
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://other.example.test/rpc/read")
                    .header("authorization", format!("Bearer {placeholder}"))
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), mismatch)
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            seen_rx.try_recv().is_err(),
            "denied requests must never reach upstream"
        );
        engine
            .reload(include_str!("../../data/sandbox-policy.rego"), POLICY)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        upstream_task.abort();
        app_task.abort();
    }

    #[test]
    fn unresolved_http2_headers_fail_closed() {
        let raw = b"POST /rpc HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer openshell:resolve:env:TOKEN\r\n\r\n";
        assert!(resolved_headers(raw, None).is_err());
    }

    #[test]
    fn grpc_message_guard_preserves_frames_at_every_transport_split() {
        let frame = b"\0\0\0\0\x05hello";
        for split in 0..=frame.len() {
            let mut guard = BodyGuard::new(None, true);
            let mut safe = guard.push(&frame[..split]).unwrap().to_vec();
            safe.extend_from_slice(&guard.push(&frame[split..]).unwrap());
            assert_eq!(safe, frame, "complete messages cannot wait for RPC end");
            assert!(guard.finish().unwrap().is_empty());
        }
    }

    #[test]
    fn grpc_message_guard_rejects_unavailable_credentials_and_unsupported_frames() {
        let token = b"openshell:resolve:env:TOKEN";
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(token.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(token);
        assert!(BodyGuard::new(None, true).push(&frame).is_err());
        assert!(BodyGuard::new(None, true).push(b"\x01\0\0\0\0").is_err());
        assert!(
            BodyGuard::new(None, true)
                .push(b"\0\xff\xff\xff\xff")
                .is_err()
        );
        let mut truncated = BodyGuard::new(None, true);
        truncated.push(b"\0\0\0\0\x05hel").unwrap();
        assert!(truncated.finish().is_err());
    }

    #[test]
    fn repeated_http2_headers_are_preserved_and_host_is_not_replaced() {
        let headers = resolved_headers(
            b"POST /rpc HTTP/1.1\r\nHost: example.com\r\nx-tag: one\r\nx-tag: two\r\n\r\n",
            None,
        )
        .unwrap();
        assert_eq!(headers.get_all("x-tag").iter().count(), 2);
        assert!(!headers.contains_key("host"));
    }
}
