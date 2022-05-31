// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Parse Secret Requests

use anyhow::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::result::Result::Ok;
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

// Struct representing the entire request
pub struct SecretRequest {
    secrets: Vec<Box<dyn SecretType>>,
}

impl Default for SecretRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretRequest {
    pub fn new() -> Self {
        SecretRequest { secrets: vec![] }
    }

    // should return Err in case of non-sensitive parsing failure
    pub fn parse_requests(&mut self, requests: &[RequestDetails]) -> Result<()> {
        for r in requests {
            let secret: Box<dyn SecretType> = match &r.secret_type[..] {
                "bundle" => Box::new(SecretBundle { request: r.clone() }),
                "key" => Box::new(SecretKey { request: r.clone() }),
                _ => return Err(anyhow!("Unknown Secret Type")),
            };

            self.secrets.push(secret);
        }

        Ok(())
    }

    pub fn policies(&self) -> Vec<policy::Policy> {
        // include tenant default
        let mut policies = vec![policy::Policy::tenant_default().unwrap()];
        for s in &self.secrets {
            policies.extend(s.policies())
        }
        policies
    }

    pub fn payload(&self) -> Result<Vec<u8>> {
        let mut payload = vec![];

        for s in &self.secrets {
            let secret_payload = s.payload()?;

            payload.extend_from_slice(&uuid_bytes_le(&Uuid::parse_str(s.guid()).unwrap()));
            payload.extend_from_slice(
                &u32::try_from(secret_payload.len() + 20)
                    .unwrap()
                    .to_le_bytes(),
            );

            payload.extend_from_slice(&secret_payload);
        }

        let mut secret_table = vec![];

        secret_table.extend_from_slice(&uuid_bytes_le(&SECRET_GUID));
        secret_table.extend_from_slice(&u32::try_from(payload.len() + 20).unwrap().to_le_bytes());
        secret_table.extend_from_slice(&payload);

        // padding: align to 16-byte boundary
        let padded_length = (secret_table.len() + 15) & !15;
        secret_table.extend_from_slice(&vec![0u8; padded_length - secret_table.len()]);

        Ok(secret_table)
    }
}

trait SecretType {
    fn payload(&self) -> Result<Vec<u8>>;
    fn policies(&self) -> Vec<policy::Policy>;
    fn guid(&self) -> &String;
}

struct SecretKey {
    request: RequestDetails,
}

impl SecretType for SecretKey {
    fn payload(&self) -> Result<Vec<u8>> {
        let key = db::get_secret(&self.request.id)?;
        Ok(match &self.request.format[..] {
            "binary" => key.into_bytes(),
            "json" => serde_json::to_string(&key).unwrap().into_bytes(),
            _ => return Err(anyhow!("Unknown format type")),
        })
    }

    fn policies(&self) -> Vec<policy::Policy> {
        match db::get_secret_policy(&self.request.id) {
            Some(p) => vec![p],
            None => vec![],
        }
    }

    fn guid(&self) -> &String {
        &self.request.guid
    }
}

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

struct SecretBundle {
    request: RequestDetails,
}

impl SecretType for SecretBundle {
    fn payload(&self) -> Result<Vec<u8>> {
        let mut bundle = HashMap::new();

        let secrets = db::get_keyset_ids(&self.request.id)?;
        for s in secrets {
            let k = db::get_secret(&s)?;
            bundle.insert(k.id, k.payload);
        }
        Ok(serde_json::to_string(&bundle)?.into_bytes())
    }

    fn policies(&self) -> Vec<policy::Policy> {
        let mut policies = vec![];
        if let Ok(keyset_policy) = db::get_keyset_policy(&self.request.id) {
            policies.push(keyset_policy);
        }

        if let Ok(secrets) = db::get_keyset_ids(&self.request.id) {
            for s in secrets {
                if let Some(policy) = db::get_secret_policy(&s) {
                    policies.push(policy);
                }
            }
        }

        policies
    }

    fn guid(&self) -> &String {
        &self.request.guid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::grpc::key_broker::RequestDetails;

    #[test]
    fn test_secret_key() {
        let secret_id = Uuid::new_v4().to_hyphenated().to_string();
        let guid = "2cf13667-ea72-4013-9dd6-155e89c5a28f".to_string();
        let request = RequestDetails {
            guid: guid.clone(),
            format: "binary".to_string(),
            secret_type: "key".to_string(),
            id: secret_id.clone(),
        };

        let secret = "test secret";
        let secret_value = base64::encode(secret);

        let secret_bytes = base64::decode(&secret_value).unwrap();

        db::insert_secret_only(&secret_id, &secret_value).unwrap();

        let secret_key = SecretKey { request };
        assert!(secret_key.policies().is_empty());
        assert_eq!(secret_key.guid(), &guid);
        assert_eq!(secret_bytes, secret_key.payload().unwrap());

        db::delete_secret(&secret_id).unwrap();
    }

    #[test]
    fn test_secret_bundle() {
        let secret_id = Uuid::new_v4().to_hyphenated().to_string();
        let bundle_id = Uuid::new_v4().to_hyphenated().to_string();
        let guid = "2cf13667-ea72-4013-9dd6-155e89c5a28f".to_string();
        let request = RequestDetails {
            guid: guid.clone(),
            format: "json".to_string(),
            secret_type: "bundle".to_string(),
            id: bundle_id.clone(),
        };

        let secret = "test secret";
        let secret_value = base64::encode(secret);

        db::insert_secret_only(&secret_id, &secret_value).unwrap();
        db::insert_keyset_only(&bundle_id, &[secret_id.clone()]).unwrap();

        let secret_bundle = SecretBundle { request };
        assert!(secret_bundle.policies().is_empty());
        assert_eq!(secret_bundle.guid(), &guid);
        let mut expected_payload = HashMap::new();
        expected_payload.insert(&secret_id, &secret_value);
        assert_eq!(
            secret_bundle.payload().unwrap(),
            serde_json::to_string(&expected_payload)
                .unwrap()
                .into_bytes()
        );

        db::delete_keyset(&bundle_id).unwrap();
        db::delete_secret(&secret_id).unwrap();
    }

    #[test]
    fn test_request_parsing() {
        let secret_id = Uuid::new_v4().to_hyphenated().to_string();
        let guid = "2cf13667-ea72-4013-9dd6-155e89c5a28f".to_string();
        let request = RequestDetails {
            guid: guid.clone(),
            format: "binary".to_string(),
            secret_type: "key".to_string(),
            id: secret_id.clone(),
        };

        let secret_value = "dGVzdCBzZWNyZXQ=".to_string(); // "test secret" -> b64
        let secret_bytes = base64::decode(&secret_value).unwrap();

        // this length is hardcoded in the struct below
        assert_eq!(secret_bytes.len(), 11);

        db::insert_secret_only(&secret_id, &secret_value).unwrap();

        let requests = vec![request];
        let mut secret_request = SecretRequest::new();
        secret_request.parse_requests(&requests).unwrap();
        let policies = secret_request.policies();

        let expected_policy = policy::Policy::tenant_default().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0], expected_policy);

        let payload = secret_request.payload().unwrap();

        #[repr(C)]
        #[derive(Serialize)]
        struct ExpectedPayload {
            table_guid: [u8; 16],
            table_length: u32,
            secret_guid: [u8; 16],
            secret_length: u32,
            secret_payload: [u8; 11],
            padding: [u8; 13],
        }

        let expected_payload = ExpectedPayload {
            table_guid: uuid_bytes_le(&SECRET_GUID),
            table_length: 51, // does not include padding
            secret_guid: uuid_bytes_le(&Uuid::parse_str(&guid).unwrap()),
            secret_length: 31, // payload size + header size
            secret_payload: secret_bytes.try_into().unwrap(),
            padding: [0u8; 13],
        };

        let expected_payload_binary = bincode::serialize(&expected_payload).unwrap();
        assert_eq!(expected_payload_binary, payload);

        db::delete_secret(&secret_id).unwrap();
    }
}
