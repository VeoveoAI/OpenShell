// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Run only under a test-owned e2e/with-docker-gateway.sh invocation. No existing
//! endpoint, model provider, registry pull or operator credential export is used.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use bollard::Docker;
use bollard::models::Volume;
use bollard::query_parameters::{
    ListContainersOptionsBuilder, ListVolumesOptionsBuilder, LogsOptionsBuilder,
    RemoveContainerOptionsBuilder,
};
use futures_util::StreamExt;
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::cli::{wait_for_healthy, wait_for_sandbox_phase};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::unique_sandbox_name;
use openshell_sdk::raw::proto;
use openshell_sdk::{DeleteOptions, EdgeAuthInterceptor, ExecOptions, OpenShellClient};
use prost_types::{Struct, Value, value::Kind};
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

const WORKDIR: &str = "/workspace/project";
const GENERATION: &str = "internal.openshell.ai/runtime-generation";
const TIMEOUT: Duration = Duration::from_secs(180);

async fn client() -> OpenShellClient {
    let name = std::env::var("OPENSHELL_GATEWAY").expect("wrapper gateway name");
    let gateway = openshell_bootstrap::load_gateway_metadata(&name).unwrap();
    assert!(!gateway.is_remote, "refusing a remote gateway");
    let url = url::Url::parse(&gateway.gateway_endpoint).unwrap();
    assert_eq!(
        url.host_str(),
        Some("127.0.0.1"),
        "test gateway must be loopback"
    );
    let mtls = PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").expect("wrapper-owned config"))
        .join("openshell/gateways")
        .join(name)
        .join("mtls");
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(
            std::fs::read(mtls.join("ca.crt")).unwrap(),
        ))
        .identity(Identity::from_pem(
            std::fs::read(mtls.join("tls.crt")).unwrap(),
            std::fs::read(mtls.join("tls.key")).unwrap(),
        ));
    let channel = Endpoint::from_shared(gateway.gateway_endpoint)
        .unwrap()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    OpenShellClient::from_parts(channel, EdgeAuthInterceptor::noop())
}

async fn snapshot(client: &OpenShellClient, name: &str) -> proto::Sandbox {
    client
        .raw_grpc()
        .get_sandbox(proto::GetSandboxRequest {
            name: name.to_string(),
            workspace_scope: Some(proto::workspace_selector("default")),
        })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap()
}

async fn exec(client: &OpenShellClient, name: &str, script: &str) -> Vec<u8> {
    let result = tokio::time::timeout(
        Duration::from_secs(45),
        client.exec(
            name,
            &["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
            ExecOptions {
                workdir: Some(WORKDIR.to_string()),
                timeout: Some(Duration::from_secs(30)),
                no_login_shell: true,
                ..Default::default()
            },
        ),
    )
    .await
    .expect("native exec deadline")
    .unwrap();
    assert_eq!(
        result.exit_code,
        0,
        "native exec failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}

fn ownership(id: &str, namespace: &str, role: &str) -> HashMap<String, String> {
    HashMap::from([
        (
            "openshell.ai/managed-by".to_string(),
            "openshell".to_string(),
        ),
        ("openshell.ai/sandbox-id".to_string(), id.to_string()),
        (
            "openshell.ai/sandbox-namespace".to_string(),
            namespace.to_string(),
        ),
        (
            "openshell.ai/isolation-backend".to_string(),
            "openshell-sandbox".to_string(),
        ),
        ("openshell.ai/isolation-role".to_string(), role.to_string()),
    ])
}

fn verify_volume(volume: &Volume, id: &str, namespace: &str) {
    assert_eq!(volume.driver, "local");
    assert!(volume.options.is_empty());
    for (key, value) in ownership(id, namespace, "workspace") {
        assert_eq!(
            volume.labels.get(&key),
            Some(&value),
            "foreign workspace volume"
        );
    }
}

async fn owned_runtime(docker: &Docker, id: &str, namespace: &str) -> String {
    let filters = HashMap::from([(
        "label".to_string(),
        ownership(id, namespace, "sandbox")
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
    )]);
    let containers = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::default()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .unwrap();
    assert_eq!(
        containers.len(),
        1,
        "expected exactly this test's workload runtime"
    );
    let container = docker
        .inspect_container(containers[0].id.as_deref().unwrap(), None)
        .await
        .unwrap();
    let labels = container.config.as_ref().unwrap().labels.as_ref().unwrap();
    for (key, value) in ownership(id, namespace, "sandbox") {
        assert_eq!(
            labels.get(&key),
            Some(&value),
            "refusing foreign runtime removal"
        );
    }
    container.id.unwrap()
}

// Only bounded stdout/stderr from this synthetic fixture's exactly owned runtime
// and supervisor. Never dump inspect config, environment or credential files.
async fn failure_diagnostics(id: &str, namespace: &str) {
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let docker = Docker::connect_with_local_defaults().map_err(|error| error.to_string())?;
        let filters = HashMap::from([("label".to_string(), vec![
            "openshell.ai/managed-by=openshell".to_string(),
            format!("openshell.ai/sandbox-id={id}"),
            format!("openshell.ai/sandbox-namespace={namespace}"),
        ])]);
        let containers = docker.list_containers(Some(ListContainersOptionsBuilder::default().all(true).filters(&filters).build())).await.map_err(|error| error.to_string())?;
        for container in containers.into_iter().take(4) {
            let Some(target) = container.id else { continue; };
            let inspected = docker.inspect_container(&target, None).await.map_err(|error| error.to_string())?;
            let Some(labels) = inspected.config.as_ref().and_then(|config| config.labels.as_ref()) else { continue; };
            let Some(role) = labels.get("openshell.ai/isolation-role") else { continue; };
            if !matches!(role.as_str(), "sandbox" | "supervisor") || !ownership(id, namespace, role).iter().all(|(key, value)| labels.get(key) == Some(value)) { continue; }
            eprintln!("persistent_workspace failure_container={target} role={role} state={:?} exit_code={:?}", inspected.state.as_ref().and_then(|state| state.status), inspected.state.as_ref().and_then(|state| state.exit_code));
            let mut logs = docker.logs(&target, Some(LogsOptionsBuilder::default().stdout(true).stderr(true).tail("40").build()));
            let mut bytes = Vec::new();
            while let Some(Ok(frame)) = logs.next().await {
                let data: &[u8] = frame.as_ref();
                bytes.extend_from_slice(&data[..data.len().min(8192 - bytes.len())]);
                if bytes.len() == 8192 { break; }
            }
            eprintln!("persistent_workspace owned_log_bytes={} role={role} log={}", bytes.len(), String::from_utf8_lossy(&bytes));
        }
        Ok::<_, String>(())
    }).await;
    if !matches!(result, Ok(Ok(()))) {
        eprintln!("persistent_workspace bounded owned diagnostics incomplete");
    }
}

// The wrapper intentionally never prunes retained volumes. On failure, first
// attempt native Delete, then reclaim only this test's verified owned objects.
struct TestCleanup {
    name: String,
    id: Option<String>,
    namespace: String,
    complete: bool,
}

impl Drop for TestCleanup {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        let name = self.name.clone();
        let id = self.id.clone();
        let namespace = self.namespace.clone();
        // Do not depend on the test's (possibly unwinding) current-thread runtime
        // to drive tonic/Docker or leave cleanup in a detached process.
        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                tokio::time::timeout(Duration::from_secs(60), async move {
                    if let Some(id) = &id {
                        failure_diagnostics(id, &namespace).await;
                    }
                    let mut command = openshell_cmd();
                    command
                        .args(["sandbox", "delete", &name])
                        .kill_on_drop(true)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    let _ = tokio::time::timeout(Duration::from_secs(30), command.status()).await;
                    let Some(id) = id else {
                        return Ok::<_, String>(());
                    };
                    let docker =
                        Docker::connect_with_local_defaults().map_err(|error| error.to_string())?;
                    let filters = HashMap::from([(
                        "label".to_string(),
                        vec![
                            "openshell.ai/managed-by=openshell".to_string(),
                            format!("openshell.ai/sandbox-id={id}"),
                            format!("openshell.ai/sandbox-namespace={namespace}"),
                        ],
                    )]);
                    for container in docker
                        .list_containers(Some(
                            ListContainersOptionsBuilder::default()
                                .all(true)
                                .filters(&filters)
                                .build(),
                        ))
                        .await
                        .map_err(|error| error.to_string())?
                    {
                        let Some(target) = container.id else {
                            continue;
                        };
                        let inspected = docker
                            .inspect_container(&target, None)
                            .await
                            .map_err(|error| error.to_string())?;
                        let Some(labels) = inspected
                            .config
                            .as_ref()
                            .and_then(|config| config.labels.as_ref())
                        else {
                            continue;
                        };
                        let Some(role) = labels.get("openshell.ai/isolation-role") else {
                            continue;
                        };
                        if !matches!(
                            role.as_str(),
                            "sandbox" | "supervisor" | "staging" | "identity"
                        ) || !ownership(&id, &namespace, role)
                            .iter()
                            .all(|(key, value)| labels.get(key) == Some(value))
                        {
                            continue;
                        }
                        docker
                            .remove_container(
                                &target,
                                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                    let volumes = docker
                        .list_volumes(Some(
                            ListVolumesOptionsBuilder::default()
                                .filters(&filters)
                                .build(),
                        ))
                        .await
                        .map_err(|error| error.to_string())?;
                    for volume in volumes.volumes.unwrap_or_default() {
                        if volume.driver != "local"
                            || !volume.options.is_empty()
                            || !ownership(&id, &namespace, "workspace")
                                .iter()
                                .all(|(key, value)| volume.labels.get(key) == Some(value))
                        {
                            continue;
                        }
                        docker
                            .remove_volume(
                                &volume.name,
                                None::<bollard::query_parameters::RemoveVolumeOptions>,
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(())
                })
                .await
                .map_err(|_| "test-owned persistent cleanup exceeded 60s".to_string())?
            })
        })
        .join();
        if !matches!(cleanup, Ok(Ok(()))) {
            eprintln!(
                "test-owned persistent cleanup incomplete; inspect only this test's exact sandbox ID and namespace"
            );
        }
    }
}

#[tokio::test]
async fn persistent_workspace_survives_native_lifecycle_runtime_loss_and_gateway_restart() {
    let began = Instant::now();
    let gateway = ManagedGateway::from_env()
        .unwrap()
        .expect("requires a wrapper-owned gateway, never existing endpoint mode");
    assert!(
        std::env::var_os("OPENSHELL_GATEWAY_ENDPOINT").is_none(),
        "existing endpoint mode refused"
    );
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap();
    assert!(
        namespace.starts_with("e2e-docker-"),
        "requires a test-owned namespace"
    );
    let image = std::env::var("OPENSHELL_DOCKER_WORKSPACE_TEST_IMAGE")
        .expect("cached immutable non-root workload image ID");
    assert!(
        image.starts_with("sha256:"),
        "refusing a mutable workload image"
    );
    let docker = Docker::connect_with_local_defaults().unwrap();
    let inspected_image = docker.inspect_image(&image).await.unwrap();
    let config = inspected_image.config.unwrap();
    assert_eq!(config.working_dir.as_deref(), Some(WORKDIR));
    assert_eq!(config.user.as_deref(), Some("1000:1000"));
    let client = client().await;
    let name = unique_sandbox_name();
    let mut guard = TestCleanup {
        name: name.clone(),
        id: None,
        namespace: namespace.clone(),
        complete: false,
    };
    let driver_config = Struct {
        fields: BTreeMap::from([(
            "docker".to_string(),
            Value {
                kind: Some(Kind::StructValue(Struct {
                    fields: BTreeMap::from([(
                        "persistent_workspace".to_string(),
                        Value {
                            kind: Some(Kind::BoolValue(true)),
                        },
                    )]),
                })),
            },
        )]),
    };
    let created = client
        .raw_grpc()
        .create_sandbox(proto::CreateSandboxRequest {
            name: name.clone(),
            workspace_scope: Some(proto::workspace_selector("default")),
            annotations: HashMap::from([(
                "openshell.nvidia.com/retention".to_string(),
                "persistent".to_string(),
            )]),
            spec: Some(proto::SandboxSpec {
                template: Some(proto::SandboxTemplate {
                    image,
                    driver_config: Some(driver_config),
                    ..Default::default()
                }),
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "while :; do sleep 3600; done".to_string(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    guard.id = Some(created.metadata.as_ref().unwrap().id.clone());
    client.wait_ready(&name, TIMEOUT).await.unwrap();
    let original = snapshot(&client, &name).await;
    let id = original.metadata.as_ref().unwrap().id.clone();
    assert_eq!(created.metadata.as_ref().unwrap().id, id);
    let trace = |stage: &str| {
        eprintln!(
            "persistent_workspace stage={stage} elapsed_ms={} sandbox_id={id} namespace={namespace}",
            began.elapsed().as_millis()
        )
    };
    trace("initial_ready");
    let fingerprint = original.host_key_fingerprint.clone();
    assert!(fingerprint.starts_with("SHA256:"));
    let marker = format!("persistent-native-{id}");
    assert_eq!(exec(&client, &name, &format!("test $(id -u) = 1000 && test $(stat -c %u .) = 1000 && test -f image-seed && printf %s '{marker}' > retained-marker && cat retained-marker")).await, marker.as_bytes());
    let runtime = owned_runtime(&docker, &id, &namespace).await;
    let inspect = docker.inspect_container(&runtime, None).await.unwrap();
    let workspace = inspect
        .mounts
        .unwrap()
        .into_iter()
        .find(|mount| mount.destination.as_deref() == Some(WORKDIR))
        .unwrap();
    let volume_name = workspace.name.unwrap();
    verify_volume(
        &docker.inspect_volume(&volume_name).await.unwrap(),
        &id,
        &namespace,
    );

    client.stop_sandbox(&name).await.unwrap();
    wait_for_sandbox_phase(&name, "Stopped", TIMEOUT)
        .await
        .unwrap();
    client.start_sandbox(&name).await.unwrap();
    client.wait_ready(&name, TIMEOUT).await.unwrap();
    assert_eq!(
        exec(&client, &name, "cat retained-marker").await,
        marker.as_bytes()
    );
    trace("stop_start_preserved");
    let before_loss = snapshot(&client, &name).await;
    assert_eq!(
        before_loss
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .get(GENERATION),
        original
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .get(GENERATION),
        "same-container Stop/Start preserves its outer-fence generation"
    );
    let runtime = owned_runtime(&docker, &id, &namespace).await;
    docker
        .remove_container(
            &runtime,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await
        .unwrap();
    wait_for_sandbox_phase(&name, "Error", TIMEOUT)
        .await
        .unwrap();
    trace("runtime_loss_retained");
    let retained = snapshot(&client, &name).await;
    assert_eq!(retained.metadata.as_ref().unwrap().id, id);
    assert_eq!(retained.spec, original.spec);
    assert_eq!(retained.host_key_fingerprint, fingerprint);
    assert!(
        retained
            .status
            .as_ref()
            .unwrap()
            .conditions
            .iter()
            .any(|condition| condition.reason == "ComputeResourceMissing")
    );
    verify_volume(
        &docker.inspect_volume(&volume_name).await.unwrap(),
        &id,
        &namespace,
    );
    client.start_sandbox(&name).await.unwrap();
    client.wait_ready(&name, TIMEOUT).await.unwrap();
    let recreated = snapshot(&client, &name).await;
    assert_eq!(recreated.metadata.as_ref().unwrap().id, id);
    assert_ne!(
        recreated
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .get(GENERATION),
        before_loss
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .get(GENERATION)
    );
    assert_eq!(recreated.spec, original.spec);
    assert_eq!(recreated.host_key_fingerprint, fingerprint);
    assert_eq!(
        exec(&client, &name, "cat retained-marker").await,
        marker.as_bytes()
    );

    trace("recreated_preserved");
    gateway.stop().unwrap();
    gateway.start().unwrap();
    wait_for_healthy(TIMEOUT).await.unwrap();
    let client = self::client().await;
    wait_for_sandbox_phase(&name, "Ready", TIMEOUT)
        .await
        .unwrap();
    let restarted = snapshot(&client, &name).await;
    assert_eq!(restarted.metadata.as_ref().unwrap().id, id);
    assert_eq!(restarted.spec, original.spec);
    assert_eq!(restarted.host_key_fingerprint, fingerprint);
    assert_eq!(
        exec(&client, &name, "cat retained-marker").await,
        marker.as_bytes()
    );
    verify_volume(
        &docker.inspect_volume(&volume_name).await.unwrap(),
        &id,
        &namespace,
    );
    trace("gateway_restart_preserved");
    eprintln!(
        "persistent_workspace sentinel_bytes={} sentinel_sha256={:x} owned_volume={volume_name}",
        marker.len(),
        Sha256::digest(marker.as_bytes())
    );
    let deletion = client
        .delete_sandbox(&name, DeleteOptions::default())
        .await
        .unwrap();
    client
        .wait_deleted(&name, TIMEOUT, deletion.sandbox_id.as_deref())
        .await
        .unwrap();
    assert!(
        matches!(
            docker.inspect_volume(&volume_name).await,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                ..
            })
        ),
        "explicit native Delete must reclaim the owned workspace volume"
    );
    trace("explicit_delete_reclaimed");
    guard.complete = true;
}
