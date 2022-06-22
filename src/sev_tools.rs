// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::db;
use anyhow::*;
use codicon::{Decoder, Encoder};
use sev::launch::sev::{HeaderFlags, Policy};
use sev::session::{Initialized, Session, Verified};
use sev::{Build, Version};

pub fn generate_launch_bundle(
    policy: u32,
    cert_chain: String,
) -> Result<(String, String, Session<Initialized>)> {
    let session = Session::try_from(Policy::from(policy)).unwrap();

    let mut bin_chain = std::io::Cursor::new(base64::decode(&cert_chain)?);
    let chain = sev::certs::Chain::decode(&mut bin_chain, ())
        .map_err(|e| anyhow!("Cert Chain not formatted correctly: {}", e))?;

    let start = session
        .start(chain)
        .map_err(|e| anyhow!("Failed to verify cert chain: {}", e))
        .unwrap();

    let mut binary_godh = std::io::Cursor::new(Vec::new());
    start.cert.encode(&mut binary_godh, ())?;

    let godh = base64::encode(&binary_godh.into_inner());
    let launch_blob = base64::encode(bincode::serialize(&start.session).unwrap());

    Ok((godh, launch_blob, session))
}

pub fn verify_measurement(
    connection: &db::Connection,
    launch_measurement: String,
    session: Session<Initialized>,
) -> Result<Session<Verified>> {
    let digest = base64::decode(&connection.fw_digest)?;

    let build = Build {
        version: Version {
            major: connection.fw_api_major as u8,
            minor: connection.fw_api_minor as u8,
        },
        build: connection.fw_build_id as u8,
    };

    let mut bin_measure = std::io::Cursor::new(base64::decode(&launch_measurement)?);
    let measure = sev::launch::sev::Measurement::decode(&mut bin_measure, ()).unwrap();

    session
        .verify(&digest, build, measure)
        .map_err(|e| anyhow!("Measurement Invalid: {}", e))
}

// All the functions in this file should take in what we get from
// gRPC and return what we need in response
// There should be no conversions in the other file
pub fn package_secret(session: Session<Verified>, secret: &[u8]) -> Result<(String, String)> {
    let secret = session.secret(HeaderFlags::default(), secret)?;
    let header = base64::encode(bincode::serialize(&secret.header)?);
    let data = base64::encode(secret.ciphertext);

    Ok((header, data))
}
