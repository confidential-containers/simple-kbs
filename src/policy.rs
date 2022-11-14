// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::db;
use anyhow::*;
use serde::Deserialize;
use std::fs;

const DEFAULT_POLICY_PATH: &str = "default_policy.json";

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct Policy {
    pub allowed_digests: Vec<String>,
    pub allowed_policies: Vec<u32>,
    pub min_fw_api_major: u32,
    pub min_fw_api_minor: u32,
    pub allowed_build_ids: Vec<u32>,
}

impl Policy {
    pub fn tenant_default() -> Result<Policy> {
        let policy_string = fs::read_to_string(DEFAULT_POLICY_PATH).map_err(|e| {
            anyhow!(
                "Default tenant configuration expected at {}. Error: {}",
                &DEFAULT_POLICY_PATH,
                e
            )
        })?;

        Ok(serde_json::from_str(&policy_string)?)
    }
}

impl Policy {
    pub fn verify(&self, connection: &db::Connection) -> Result<()> {
        if !self.allowed_digests.is_empty()
            && !self
                .allowed_digests
                .contains(&connection.fw_digest.to_string())
        {
            return Err(anyhow!("fw digest not valid"));
        }

        if !self.allowed_policies.is_empty() && !self.allowed_policies.contains(&connection.policy)
        {
            return Err(anyhow!("policy not valid"));
        }

        if connection.fw_api_major < self.min_fw_api_major {
            return Err(anyhow!("fw api major not valid"));
        }

        // if we have exactly the minimum required major version,
        // check that the minor version is appropriate.
        if connection.fw_api_major == self.min_fw_api_major
            && connection.fw_api_minor < self.min_fw_api_minor
        {
            return Err(anyhow!("fw api minor not valid"));
        }

        if !self.allowed_build_ids.is_empty()
            && !self.allowed_build_ids.contains(&connection.fw_build_id)
        {
            return Err(anyhow!("build id not valid"));
        }

        Ok(())
    }
}
