// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Parse Secret Requests

use anyhow::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::db;
use crate::grpc::key_broker::RequestDetails;
use crate::policy;

// GUID that marks the beginning of the secret table:
// 1e74f542-71dd-4d66-963e-ef4287ff173b
const SECRET_GUID: Uuid = Uuid::from_bytes([
    0x1e, 0x74, 0xf5, 0x42, 0x71, 0xdd, 0x4d, 0x66, 0x96, 0x3e, 0xef, 0x42, 0x87, 0xff, 0x17, 0x3b,
]);

fn uuid_bytes_le(u: &Uuid) -> [u8; 16] {
    let b = u.as_bytes();
    let r: [u8; 16] = [
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15],
    ];
    r
}

#[derive(Serialize, Deserialize)]
struct Request {
    guid: String,
    format: String,
    secret_type: String,
    id: String,
}

#[derive(Serialize, Deserialize)]
struct RequestList {
    requests: Vec<Request>,
}

// we need two serialization methods
// either to binary, which turns a key just into
// a binary payload or string which we use for json serialization
#[derive(Serialize, Deserialize, Default)]
pub struct Key {
    pub id: String,
    pub payload: String,
}

impl Key {
    pub fn into_bytes(&self) -> Vec<u8> {
        base64::decode(&self.payload).unwrap()
    }
}

pub struct SecretRequest {
    policies: Vec<policy::Policy>,
    payload: Vec<u8>,
}

impl SecretRequest {
    pub fn new(requests: &[RequestDetails]) -> Result<Self> {
        // include tenant default policy
        let mut policies = vec![policy::Policy::tenant_default()?];

        // vector for payload
        // this does not include the header
        let mut payload = vec![];

        // TODO: separate this into multiple functions
        //       and create a trait for secret types so that we can
        //       easily add more
        for r in requests {
            // for each request we must create guided entry in the table
            // this match should give us the payload for the guided entry
            let guid_payload = match &r.secret_type[..] {
                "bundle" => {
                    if r.format == "binary" {
                        return Err(anyhow!("Bundle format must be JSON"));
                    }

                    let mut bundle = HashMap::new();
                    if let Some(pid) = db::get_keyset_policy(&r.id) {
                        policies.push(pid);
                    }
                    let secrets = db::get_keyset_ids(&r.id)?;
                    for s in secrets {
                        // make header format
                        if let Some(p) = db::get_secret_policy(&s) {
                            policies.push(p);
                        }
                        if let Some(k) = db::get_secret(&s) {
                            bundle.insert(k.id, k.payload);
                        }
                    }
                    serde_json::to_string(&bundle)?.into_bytes()
                }
                "key" => {
                    if let Some(p) = db::get_secret_policy(&r.id) {
                        policies.push(p);
                    }
                    if let Some(key) = db::get_secret(&r.id) {
                        match &r.format[..] {
                            "binary" => key.into_bytes(),
                            "json" => serde_json::to_string(&key)?.into_bytes(),
                            _ => return Err(anyhow!("Invalid secret format.")),
                        }
                    } else {
                        return Err(anyhow!("Invalid secret format."));
                    }
                }
                "resource" => {
                    // TODO
                    b"placeholder".to_vec()
                }
                _ => return Err(anyhow!("Unknown Secret Type")),
            };

            payload.extend_from_slice(&uuid_bytes_le(&Uuid::parse_str(&r.guid).unwrap()));
            payload.extend_from_slice(
                &u32::try_from(guid_payload.len() + 20)
                    .unwrap()
                    .to_le_bytes(),
            );

            payload.extend_from_slice(&guid_payload);
        }

        // Construct the secret header with the secret guid
        let mut secret_table = vec![];

        secret_table.extend_from_slice(&uuid_bytes_le(&SECRET_GUID));
        secret_table.extend_from_slice(&u32::try_from(payload.len() + 20).unwrap().to_le_bytes());
        secret_table.extend_from_slice(&payload);

        // padding: align to 16-byte boundary
        let padded_length = (secret_table.len() + 15) & !15;
        secret_table.extend_from_slice(&vec![0u8; padded_length - secret_table.len()]);

        Ok(SecretRequest {
            policies,
            payload: secret_table,
        })
    }

    pub fn get_policies(&self) -> &Vec<policy::Policy> {
        &self.policies
    }

    pub fn get_payload(&self) -> &Vec<u8> {
        &self.payload
    }
}
