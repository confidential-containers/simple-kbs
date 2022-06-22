// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use log::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

extern crate lazy_static;

use crate::db;
use crate::request;
use crate::sev_tools::{generate_launch_bundle, package_secret, verify_measurement};

use sev::session::{Initialized, Session};

use key_broker::key_broker_service_server::{KeyBrokerService, KeyBrokerServiceServer};
use key_broker::{BundleRequest, BundleResponse, SecretRequest, SecretResponse};

// Keep the session for each connection in memory.
lazy_static::lazy_static! {
    pub static ref SESSIONS: Arc<Mutex<HashMap<Uuid,Session<Initialized>>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub mod key_broker {
    tonic::include_proto!("keybroker");
}

#[derive(Debug, Default)]
pub struct KeyBroker {}

#[tonic::async_trait]
impl KeyBrokerService for KeyBroker {
    async fn get_bundle(
        &self,
        request: Request<BundleRequest>,
    ) -> Result<Response<BundleResponse>, Status> {
        let r = request.into_inner();

        info!("Launch Bundle Requested");

        // validate certificate chain
        let (godh, launch_blob, session) = generate_launch_bundle(r.policy, r.certificate_chain)
            .map_err(|e| Status::internal(format!("Failed to generate launch bundle: {}", e)))?;

        let launch_id = Ok(Uuid::new_v4()).unwrap();
        SESSIONS.lock().unwrap().insert(launch_id, session);

        let reply = BundleResponse {
            guest_owner_public_key: godh,
            launch_blob,
            launch_id: launch_id.to_string(),
        };

        Result::Ok(Response::new(reply))
    }

    async fn get_secret(
        &self,
        request: Request<SecretRequest>,
    ) -> Result<Response<SecretResponse>, Status> {
        info!("Secret Requested");

        // Get connection from DB using connection ID
        let r = request.into_inner();
        let launch_id = Uuid::parse_str(&r.launch_id)
            .map_err(|e| Status::internal(format!("Malformed Launch ID: {}", e)))?;

        // keep track of the connection
        let connection = db::Connection {
            policy: r.policy,
            fw_api_major: r.api_major,
            fw_api_minor: r.api_minor,
            fw_build_id: r.build_id,
            launch_description: r.launch_description,
            fw_digest: r.fw_digest,
        };

        let mut secret_request = request::SecretRequest::new();

        secret_request
            .parse_requests(&r.secret_requests)
            .map_err(|e| Status::internal(format!("Bad secret request: {}", e)))?;

        let policies = secret_request.policies();

        // Validate connection against policies
        for p in policies {
            p.verify(&connection)
                .map_err(|e| Status::internal(format!("Policy validation failed: {}", e)))?;
        }
        info!(
            "Policy validated succesfully. Connection: {:?}",
            &connection
        );

        let session = SESSIONS.lock().unwrap().remove(&launch_id).ok_or_else(|| {
            Status::internal(format!("Launch ID not found. UUID: {}", &launch_id))
        })?;

        // verify launch measurement
        let session_verified = verify_measurement(&connection, r.launch_measurement, session)
            .map_err(|e| Status::internal(format!("Measurement Verification Failed: {}", e)))?;

        // get secret(s)
        let secret_payload = &secret_request
            .payload(&connection)
            .map_err(|e| Status::internal(format!("Cannot fulfill secret request: {}", e)))?;

        let (secret_header, secret_data) = package_secret(session_verified, secret_payload)
            .map_err(|e| Status::internal(format!("Failed to package secret: {}", e)))?;

        let reply = SecretResponse {
            launch_secret_header: secret_header,
            launch_secret_data: secret_data,
        };
        Result::Ok(Response::new(reply))
    }
}

pub async fn start_service(socket: SocketAddr) -> Result<()> {
    let service = KeyBroker::default();
    let _server = Server::builder()
        .add_service(KeyBrokerServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
