// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Parse Secret Requests

use anyhow::*;
use async_trait::async_trait;
use log::*;
use ring::{rand::SystemRandom, signature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::result::Result::Ok;
use uuid::Uuid;

use crate::db;
use crate::grpc::key_broker::RequestDetails;
use crate::policy;

// GUID that marks the beginning of the secret table
const SECRET_GUID: Uuid = uuid::uuid!("1e74f542-71dd-4d66-963e-ef4287ff173b");

// Struct representing the entire request
pub struct SecretRequest {
    secrets: Vec<Box<dyn SecretType + Send + Sync>>,
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
            let secret: Box<dyn SecretType + Send + Sync> = match &r.secret_type[..] {
                "bundle" => Box::new(SecretBundle { request: r.clone() }),
                "key" => Box::new(SecretKey { request: r.clone() }),
                "report" => Box::new(SecretReport { request: r.clone() }),
                "connection" => Box::new(SecretConnection { request: r.clone() }),
                _ => return Err(anyhow!("Unknown Secret Type")),
            };

            self.secrets.push(secret);
        }

        Ok(())
    }

    pub async fn policies(&self) -> Vec<policy::Policy> {
        // include tenant default
        let mut policies = vec![policy::Policy::tenant_default().unwrap()];
        for s in &self.secrets {
            policies.extend(s.policies().await)
        }
        policies
    }

    pub async fn payload(&self, connection: &db::Connection) -> Result<Vec<u8>> {
        let mut payload = vec![];

        for s in &self.secrets {
            let secret_payload = s.payload(connection.clone()).await?;

            payload.extend_from_slice(&Uuid::parse_str(s.guid()).unwrap().to_bytes_le());
            payload.extend_from_slice(
                &u32::try_from(secret_payload.len() + 20)
                    .unwrap()
                    .to_le_bytes(),
            );

            payload.extend_from_slice(&secret_payload);
        }

        let mut secret_table = vec![];

        secret_table.extend_from_slice(&SECRET_GUID.to_bytes_le());
        secret_table.extend_from_slice(&u32::try_from(payload.len() + 20).unwrap().to_le_bytes());
        secret_table.extend_from_slice(&payload);

        // padding: align to 16-byte boundary
        let padded_length = (secret_table.len() + 15) & !15;
        secret_table.extend_from_slice(&vec![0u8; padded_length - secret_table.len()]);

        Ok(secret_table)
    }
}

#[async_trait]
trait SecretType {
    async fn payload(&self, connection: db::Connection) -> Result<Vec<u8>>;
    async fn policies(&self) -> Vec<policy::Policy>;
    fn guid(&self) -> &String;
}

struct SecretKey {
    request: RequestDetails,
}

#[async_trait]
impl SecretType for SecretKey {
    #[allow(unused_variables)]
    async fn payload(&self, connection: db::Connection) -> Result<Vec<u8>> {
        let key = db::get_secret(&self.request.id).await?;
        Ok(match &self.request.format[..] {
            "binary" => key.into_bytes(),
            "json" => serde_json::to_string(&key).unwrap().into_bytes(),
            _ => return Err(anyhow!("Unknown format type")),
        })
    }

    async fn policies(&self) -> Vec<policy::Policy> {
        match db::get_secret_policy(&self.request.id).await {
            Ok(policy) => vec![policy],
            Err(e) => {
                error!(
                    "Error getting policy for secret with id {}. Details: {}",
                    &self.request.id, e
                );
                vec![]
            }
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

#[async_trait]
impl SecretType for SecretBundle {
    #[allow(unused_variables)]
    async fn payload(&self, connection: db::Connection) -> Result<Vec<u8>> {
        let mut bundle = HashMap::new();

        let secrets = db::get_keyset_ids(&self.request.id).await?;
        for s in secrets {
            let k = db::get_secret(&s).await?;
            bundle.insert(k.id, k.payload);
        }
        Ok(serde_json::to_string(&bundle)?.into_bytes())
    }

    // Policies are calculated before the measurement is validated.
    // Since the guest/client is not trusted at this point, errors are
    // not reported to it. Thus, this method does not return a result.
    async fn policies(&self) -> Vec<policy::Policy> {
        let mut policies = vec![];

        match db::get_keyset_policy(&self.request.id).await {
            Ok(policy) => policies.push(policy),
            Err(e) => {
                error!(
                    "Error getting policy for keyset with id {}. Details: {}",
                    &self.request.id, e
                )
            }
        }

        if let Ok(secrets) = db::get_keyset_ids(&self.request.id).await {
            for s in secrets {
                match db::get_secret_policy(&s).await {
                    Ok(policy) => policies.push(policy),
                    Err(e) => {
                        error!(
                            "Error getting policy for secret with id {}. Details: {}",
                            &s, e
                        )
                    }
                }
            }
        }

        policies
    }

    fn guid(&self) -> &String {
        &self.request.guid
    }
}

/*
 * The Report secret type is a signed copy of the connection.
 *
 * A KBC can use this to prove that the guest verified by the KBS
 * and was launched with certain parameters.
 */

struct SecretReport {
    request: RequestDetails,
}

#[derive(Serialize, Deserialize)]
struct Report {
    connection: String,
    signature: String,
}

#[async_trait]
impl SecretType for SecretReport {
    async fn payload(&self, connection: db::Connection) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();

        let key_pair_pkcs8 = db::get_report_keypair(&self.request.id).await?;
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &key_pair_pkcs8,
        )
        .map_err(|_| anyhow!("Failed to load keypair"))?;

        let connection_string = serde_json::to_string(&connection)?;
        let connection_bytes = connection_string.clone().into_bytes();

        let signature = key_pair
            .sign(&rng, &connection_bytes)
            .map_err(|_| anyhow!("Failed to sign connection."))?;

        let report = Report {
            connection: connection_string,
            signature: base64::encode(signature.as_ref()),
        };

        Ok(serde_json::to_vec(&report)?)
    }

    async fn policies(&self) -> Vec<policy::Policy> {
        match db::get_signing_keys_policy(&self.request.id).await {
            Ok(policy) => match policy {
                Some(p) => vec![p],
                None => vec![],
            },
            Err(e) => {
                error!(
                    "Error getting policy for secret with id {}. Details: {}",
                    &self.request.id, e
                );
                vec![]
            }
        }
    }

    fn guid(&self) -> &String {
        &self.request.guid
    }
}

struct SecretConnection {
    request: RequestDetails,
}

#[derive(Serialize)]
struct ConnectionOutput {
    connection_id: Uuid,
    key: String,
}

#[async_trait]
impl SecretType for SecretConnection {
    async fn payload(&self, connection: db::Connection) -> Result<Vec<u8>> {
        let (connection_id, key) = db::insert_connection(connection).await?;
        let output = ConnectionOutput { connection_id, key };

        Ok(bincode::serialize(&output)?)
    }

    // Secrets requested later using this connection will
    // have their policies validated against the initial
    // parameters of the connection. Only the default policy
    // must be met to get a connection.
    async fn policies(&self) -> Vec<policy::Policy> {
        vec![]
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
    use ring::signature::KeyPair;

    #[tokio::test]
    async fn test_secret_key() {
        let secret_id = Uuid::new_v4().as_hyphenated().to_string();
        let guid = "2cf13667-ea72-4013-9dd6-155e89c5a28f".to_string();
        let connection = db::Connection::default();
        let request = RequestDetails {
            guid: guid.clone(),
            format: "binary".to_string(),
            secret_type: "key".to_string(),
            id: secret_id.clone(),
        };

        let secret = "test secret";
        let secret_value = base64::encode(secret);

        let secret_bytes = base64::decode(&secret_value).unwrap();

        db::insert_secret(&secret_id, &secret_value, None)
            .await
            .unwrap();

        let secret_key = SecretKey { request };
        assert!(secret_key.policies().await.is_empty());
        assert_eq!(secret_key.guid(), &guid);
        assert_eq!(secret_bytes, secret_key.payload(connection).await.unwrap());

        db::delete_secret(&secret_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_secret_bundle() {
        let secret_id = Uuid::new_v4().as_hyphenated().to_string();
        let bundle_id = Uuid::new_v4().as_hyphenated().to_string();
        let guid = "2cf13667-ea72-4013-9dd6-155e89c5a28f".to_string();
        let connection = db::Connection::default();
        let request = RequestDetails {
            guid: guid.clone(),
            format: "json".to_string(),
            secret_type: "bundle".to_string(),
            id: bundle_id.clone(),
        };

        let secret = "test secret";
        let secret_value = base64::encode(secret);

        db::insert_secret(&secret_id, &secret_value, None)
            .await
            .unwrap();
        db::insert_keyset(&bundle_id, &[secret_id.clone()], None)
            .await
            .unwrap();

        let secret_bundle = SecretBundle { request };
        assert!(secret_bundle.policies().await.is_empty());
        assert_eq!(secret_bundle.guid(), &guid);
        let mut expected_payload = HashMap::new();
        expected_payload.insert(&secret_id, &secret_value);
        assert_eq!(
            secret_bundle.payload(connection).await.unwrap(),
            serde_json::to_string(&expected_payload)
                .unwrap()
                .into_bytes()
        );

        db::delete_keyset(&bundle_id).await.unwrap();
        db::delete_secret(&secret_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_report() {
        // setup test state
        let guid = "2cf13667-ea72-4013-9dd6-155e89c5a28f".to_string();
        let kid = "test-keypair".to_string();

        let rng = SystemRandom::new();
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_bytes.as_ref(),
        )
        .unwrap();

        let public_key = key_pair.public_key().as_ref();
        db::insert_report_keypair(&kid, pkcs8_bytes.as_ref(), None)
            .await
            .unwrap();

        let connection = db::Connection::default();

        // create secret request
        let request = RequestDetails {
            guid: guid.clone(),
            format: "json".to_string(),
            secret_type: "report".to_string(),
            id: kid.clone(),
        };

        let r = SecretReport { request };

        // test policy
        assert!(r.policies().await.is_empty());

        // get report payload
        let payload = r.payload(connection.clone()).await.unwrap();
        let report: Report = serde_json::from_slice(&payload).unwrap();

        // make sure the connection in the report matches
        let conn: db::Connection = serde_json::from_str(&report.connection).unwrap();
        assert_eq!(conn.launch_description, connection.launch_description);

        // verify report signature
        let connection_bytes = report.connection.into_bytes();
        let signature_bytes = base64::decode(report.signature).unwrap();

        let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key);

        key.verify(&connection_bytes, &signature_bytes).unwrap();

        db::delete_report_keypair(&kid).await.unwrap();
    }

    #[tokio::test]
    async fn test_request_parsing() {
        let secret_id = Uuid::new_v4().as_hyphenated().to_string();
        let guid = "2cf13667-ea72-4013-9dd6-155e89c5a28f".to_string();
        let connection = db::Connection::default();
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

        db::insert_secret(&secret_id, &secret_value, None)
            .await
            .unwrap();

        let requests = vec![request];
        let mut secret_request = SecretRequest::new();
        secret_request.parse_requests(&requests).unwrap();
        let policies = secret_request.policies().await;

        let expected_policy = policy::Policy::tenant_default().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0], expected_policy);

        let payload = secret_request.payload(&connection).await.unwrap();

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
            table_guid: SECRET_GUID.to_bytes_le(),
            table_length: 51, // does not include padding
            secret_guid: Uuid::parse_str(&guid).unwrap().to_bytes_le(),
            secret_length: 31, // payload size + header size
            secret_payload: secret_bytes.try_into().unwrap(),
            padding: [0u8; 13],
        };

        let expected_payload_binary = bincode::serialize(&expected_payload).unwrap();
        assert_eq!(expected_payload_binary, payload);

        db::delete_secret(&secret_id).await.unwrap();
    }
}
