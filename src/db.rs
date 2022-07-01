// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::policy;
use crate::request;

use anyhow::*;
<<<<<<< HEAD
use mysql::{OptsBuilder, Pool, PooledConn, TxOpts};
use serde::{Deserialize, Serialize};
=======
>>>>>>> 4e8c96a (First commits to convert database handling to sqlx.)
use std::env;
use std::result::Result::Ok;
use uuid::Uuid;

use serde::{Deserialize, Serialize};
use sqlx::any::AnyPoolOptions;
use sqlx::AnyPool;
use sqlx::Row;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub policy: u32,
    pub fw_api_major: u32,
    pub fw_api_minor: u32,
    pub fw_build_id: u32,
    pub launch_description: String,
    pub fw_digest: String,
}

impl Default for Connection {
    fn default() -> Connection {
        Connection {
            policy: 0x0,
            fw_api_major: 0,
            fw_api_minor: 0,
            fw_build_id: 14,
            launch_description: "test".to_string(),
            fw_digest: "placeholder".to_string(),
        }
    }
}

pub async fn get_dbpool() -> Result<AnyPool> {
    let db_type = env::var("KBS_DB_TYPE").expect("KBS_DB_TYPE not set");
    let host_name = env::var("KBS_DB_HOST").expect("KBS_DB_HOST not set");
    let user_name = env::var("KBS_DB_USER").expect("KBS_DB_USER not set.");
    let db_pw = env::var("KBS_DB_PW").expect("KBS_DB_PW not set.");
    let data_base = env::var("KBS_DB").expect("KBS_DB not set");

    let db_url = format!(
        "{}://{}:{}@{}/{}",
        db_type, user_name, db_pw, host_name, data_base
    );

    let db_pool = AnyPoolOptions::new()
        .max_connections(1000)
        .connect(&db_url)
        .await
        .map_err(|e| anyhow!("Encountered error trying to create a mysql pool: {}", e))?;
    Ok(db_pool)
}

pub async fn insert_connection(connection: Connection) -> Result<Uuid> {
    let dbpool = get_dbpool().await?;

    let nwuuid = Uuid::new_v4();
    let uuidstr = nwuuid.as_hyphenated().to_string();

    let query = format!("insert into conn_bundle (id, policy, fw_api_major, fw_api_minor, fw_build_id, launch_description, fw_digest, create_date) VALUES(\"{}\", {}, {}, {}, {}, \"{}\", \"{}\", NOW())", 
     uuidstr,
     connection.policy,
     connection.fw_api_major,
     connection.fw_api_minor,
     connection.fw_build_id,
     connection.launch_description,
     connection.fw_digest
     );

    sqlx::query(query.as_str()).execute(&dbpool).await?;

    Ok(nwuuid)
}

pub async fn get_connection(uuid: Uuid) -> Result<Connection> {
    let dbpool = get_dbpool().await?;

    let uuidstr = uuid.as_hyphenated().to_string();
    let query = format!("SELECT policy, fw_api_major, fw_api_minor, fw_build_id, launch_description, fw_digest FROM conn_bundle WHERE id = \"{}\"", uuidstr);

    let con_row = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;

    Ok(Connection {
        policy: con_row.try_get::<i32, _>(0)? as u32,
        fw_api_major: con_row.try_get::<i32, _>(1)? as u32,
        fw_api_minor: con_row.try_get::<i32, _>(2)? as u32,
        fw_build_id: con_row.try_get::<i32, _>(3)? as u32,
        launch_description: con_row.try_get::<String, _>(4)?,
        fw_digest: con_row.try_get::<String, _>(5)?,
    })
}

pub async fn delete_connection(uuid: Uuid) -> Result<Uuid> {
    let dbpool = get_dbpool().await?;

    let query = format!(
        "DELETE from conn_bundle WHERE id = \"{}\"",
        uuid.as_hyphenated()
    );

    sqlx::query(query.as_str()).execute(&dbpool).await?;
    Ok(uuid)
}

pub async fn insert_policy(policy: &policy::Policy) -> Result<u64> {
    let dbpool = get_dbpool().await?;

    //let allowed_digests_json = serde_json::to_string(&policy.allowed_digests)?;
    //let allowed_policy_json = serde_json::to_string(&policy.allowed_policies)?;
    //let allowed_build_ids_json = serde_json::to_string(&policy.allowed_build_ids)?;

    let mut dbconn = get_dbconn()?;
    let query = format!(
        "INSERT INTO policy (allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor, allowed_build_ids, create_date, valid) VALUES(\'{:?}\', \'{:?}\', {}, {}, \'{:?}\', NOW(), 1)",
        policy.allowed_digests,
        policy.allowed_policies,
        policy.min_fw_api_major,
        policy.min_fw_api_minor,
        policy.allowed_build_ids
    );

    let last_insert_row = sqlx::query(query.as_str())
        .execute(&dbpool)
        .await?
        .last_insert_id();

    let last_insert_id = last_insert_row.unwrap();

    Ok(last_insert_id as u64)
}

pub async fn get_policy(pid: u64) -> Result<policy::Policy> {
    let dbpool = get_dbpool().await?;

    let query = format!("SELECT allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor, allowed_build_ids FROM policy WHERE id = {} AND valid = 1", pid);
    let row_vec = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;
    Ok(policy::Policy {
        allowed_digests: serde_json::from_str(&row_vec.try_get::<String, _>(0)?).unwrap(),
        allowed_policies: serde_json::from_str(&row_vec.try_get::<String, _>(1)?).unwrap(),
        min_fw_api_major: row_vec.try_get::<i32, _>(2)? as u32,
        min_fw_api_minor: row_vec.try_get::<i32, _>(3)? as u32,
        allowed_build_ids: serde_json::from_str(&row_vec.try_get::<String, _>(4)?).unwrap(),
    })
}

pub async fn get_secret_policy(sec: &str) -> Result<policy::Policy> {
    let dbpool = get_dbpool().await?;

    let query = format!("SELECT polid FROM secrets WHERE secret_id = \'{}\'", sec);

    let val_row = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;

    let val = val_row.try_get::<i32, _>(0)? as u64;
    let secret_policy = get_policy(val).await?;
    Ok(secret_policy)
}

pub async fn delete_policy(pid: &u64) -> Result<()> {
    let dbpool = get_dbpool().await?;

    let query = format!("DELETE from policy WHERE id = {}", pid);
    sqlx::query(query.as_str()).execute(&dbpool).await?;
    Ok(())
}

pub async fn insert_keyset(ksetid: &str, kskeys: &[String], polid: Option<u32>) -> Result<()> {
    let dbpool = get_dbpool().await?;

    // Create JSON for vector struct member variables
    let kskeys_str = serde_json::to_string(kskeys)?;

    let query = match polid {
        Some(p) => format!(
            "INSERT INTO keysets (keysetid, kskeys, polid) VALUES(\'{}\', \'{}\', {})",
            ksetid, kskeys_str, p
        ),
        None => format!(
            "INSERT INTO keysets (keysetid, kskeys) VALUES( \'{}\', \'{}\')",
            ksetid, kskeys_str
        ),
    };

    sqlx::query(query.as_str()).execute(&dbpool).await?;

    Ok(())
}

pub async fn delete_keyset(ksetid: &str) -> Result<()> {
    let dbpool = get_dbpool().await?;

    /* create JSON for vector struct member variables */

    let query = format!("DELETE from keysets WHERE keysetid = \'{}\'", ksetid);

    sqlx::query(query.as_str()).execute(&dbpool).await?;

    Ok(())
}

pub async fn get_keyset_policy(keysetid: &str) -> Result<policy::Policy> {
    let dbpool = get_dbpool().await?;

    let query = format!(
        "SELECT polid FROM keysets WHERE keysetid = \'{}\'",
        keysetid
    );

    let polid_row = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;

    let keyset_policy_id = polid_row.try_get::<i32, _>(0)? as u64;

    let retpol = get_policy(keyset_policy_id).await?;

    Ok(retpol)
}

pub async fn get_keyset_ids(keyset_id: &str) -> Result<Vec<String>> {
    let dbpool = get_dbpool().await?;

    let query = format!(
        "SELECT kskeys FROM keysets WHERE keysetid = \'{}\'",
        keyset_id
    );

    let keyset_row = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;

    let rks: Vec<String> = serde_json::from_str(&keyset_row.try_get::<String, _>(0)?).unwrap();

    Ok(rks)
}

pub async fn get_secret(secret_id: &str) -> Result<request::Key> {
    let dbpool = get_dbpool().await?;

    let query = format!(
        "SELECT secret FROM secrets WHERE secret_id = \'{}\'",
        secret_id
    );

    let payload_row = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;

    let payload = payload_row.try_get::<String, _>(0)?;

    Ok(request::Key {
        id: secret_id.to_string(),
        payload,
    })
}

pub async fn insert_secret(secret_id: &str, secret: &str, policy_id: Option<u64>) -> Result<()> {
    let dbpool = get_dbpool().await?;

    let query = match policy_id {
        Some(p) => format!(
            "INSERT INTO secrets (secret_id, secret, polid ) VALUES(\'{}\', \'{}\', {:?})",
            secret_id, secret, p
        ),
        None => format!(
            "INSERT INTO secrets (secret_id, secret ) VALUES(\'{}\', \'{}\')",
            secret_id, secret
        ),
    };

    sqlx::query(query.as_str()).execute(&dbpool).await?;

    Ok(())
}

pub async fn delete_secret(secret_id: &str) -> Result<()> {
    let dbpool = get_dbpool().await?;

    let query = format!("DELETE from secrets WHERE secret_id = \'{}\'", secret_id);

    sqlx::query(query.as_str()).execute(&dbpool).await?;

    Ok(())
}

pub fn insert_report_keypair(id: &str, keypair: &[u8], policy_id: Option<u64>) -> Result<()> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    let keypair_b64 = base64::encode(&keypair);
    let mqstr = "INSERT INTO report_keypair (key_id, keypair, polid) VALUES(?, ?, ?)";

    trnsx.exec_drop(mqstr, (&id, &keypair_b64, &policy_id))?;
    trnsx.commit()?;

    Ok(())
}

pub fn get_report_keypair(id: &str) -> Result<Vec<u8>> {
    let mut dbconn = get_dbconn()?;

    let mqstr = "SELECT keypair FROM report_keypair WHERE key_id = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;
    let keys: Option<String> = trnsx.exec_first(mqstr, (id,))?;
    let kp = keys.ok_or_else(|| anyhow!("report signing key not found"))?;

    let kp_bytes = base64::decode(&kp)?;

    Ok(kp_bytes)
}

pub fn delete_report_keypair(key_id: &str) -> Result<()> {
    let mut dbconn = get_dbconn()?;

    let mqstr = "DELETE FROM report_keypair WHERE key_id = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (key_id,))?;
    trnsx.commit()?;
    Ok(())
}

pub fn get_signing_keys_policy(key_id: &str) -> Result<Option<policy::Policy>> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    let mqstr = "SELECT polid FROM report_keypair WHERE key_id = ? AND polid IS NOT NULL";

    let policy_id: Option<u64> = trnsx.exec_first(mqstr, (key_id,))?;

    if let Some(id) = policy_id {
        Ok(Some(get_policy(id)?))
    } else {
        Ok(None)
    }
}

    Ok(())
}

// ------------------------------------------------------------------------------------

pub async fn insert_report_keypair(id: &str, keypair: &[u8], policy_id: Option<u64>) -> Result<()> {
    let dbpool = get_dbpool().await?;

    let keypair_b64 = base64::encode(&keypair);

    let query = match policy_id {
        Some(p) => format!(
            "INSERT INTO report_keypair (key_id, keypair, polid) VALUES(\'{}\', \'{}\', {:?})",
            id, keypair_b64, p
        ),
        None => format!(
            "INSERT INTO report_keypair (key_id, keypair) VALUES(\'{}\', \'{}\')",
            id, keypair_b64
        ),
    };

    sqlx::query(query.as_str()).execute(&dbpool).await?;

    Ok(())
}

pub async fn get_report_keypair(id: &str) -> Result<Vec<u8>> {
    let dbpool = get_dbpool().await?;

    let query = format!(
        "SELECT keypair FROM report_keypair WHERE key_id = \'{}\'",
        id
    );

    let keys_row = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;

    let kp = keys_row.try_get::<String, _>(0)?;
    let kp_bytes = base64::decode(&kp)?;

    Ok(kp_bytes)
}

pub async fn delete_report_keypair(key_id: &str) -> Result<()> {
    let dbpool = get_dbpool().await?;

    let query = format!("DELETE FROM report_keypair WHERE key_id = \'{}\'", key_id);

    sqlx::query(query.as_str()).execute(&dbpool).await?;

    Ok(())
}

pub async fn get_signing_keys_policy(key_id: &str) -> Result<Option<policy::Policy>> {
    let dbpool = get_dbpool().await?;

    let query = format!(
        "SELECT polid FROM report_keypair WHERE key_id = \'{}\' AND polid IS NOT NULL",
        key_id
    );

    let policy_id_row = sqlx::query(query.as_str()).fetch_one(&dbpool).await?;

    let policy_id = policy_id_row.try_get::<i32, _>(0)? as u64;
    Ok(Some(get_policy(policy_id).await?))
}

// -----------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_connection() -> anyhow::Result<()> {
        let testconn = Connection::default();

        let tid = aw!(insert_connection(testconn.clone()))?;

        let resconn = aw!(get_connection(tid.clone()))?;

        assert_eq!(testconn.policy, resconn.policy);
        assert_eq!(testconn.fw_api_major, resconn.fw_api_major);
        assert_eq!(testconn.fw_api_minor, resconn.fw_api_minor);
        assert_eq!(testconn.fw_build_id, resconn.fw_build_id);
        assert_eq!(testconn.launch_description, resconn.launch_description);
        let _dconid = aw!(delete_connection(tid.clone()))?;

        Ok(())
    }

    #[test]
    fn test_insert_policy() -> anyhow::Result<()> {
        let testpol = policy::Policy {
            allowed_digests: vec!["0".to_string(), "1".to_string(), "3".to_string()],
            allowed_policies: vec![0u32, 1u32, 2u32],
            min_fw_api_major: 0,
            min_fw_api_minor: 0,
            allowed_build_ids: vec![0u32, 1u32, 2u32],
        };

        let polid = aw!(insert_policy(&testpol))?;

        let rpol = aw!(get_policy(polid))?;

        for j in 0..2 {
            assert_eq!(
                rpol.allowed_digests[j].clone(),
                testpol.allowed_digests[j].clone()
            );
        }

        for j in 0..2 {
            assert_eq!(
                rpol.allowed_policies[j].clone(),
                testpol.allowed_policies[j].clone()
            );
        }

        assert_eq!(rpol.min_fw_api_major.clone(), 0);
        assert_eq!(rpol.min_fw_api_minor.clone(), 0);

        for j in 0..2 {
            assert_eq!(
                rpol.allowed_build_ids[j].clone(),
                testpol.allowed_build_ids[j].clone()
            );
        }

        aw!(delete_policy(&polid))?;
        Ok(())
    }

    #[test]
    fn test_secret_policy() -> anyhow::Result<()> {
        let tinspol = policy::Policy {
            allowed_digests: vec![
                "PuBT5e0dD21ZDoqdiBMNjWeKV2WhtcEOIdWeEsFwivw=".to_string(),
                "1".to_owned(),
                "3".to_owned(),
            ],
            allowed_policies: vec![0u32, 1u32, 2u32],
            min_fw_api_major: 23,
            min_fw_api_minor: 0,
            allowed_build_ids: vec![0u32, 1u32, 2u32],
        };

        let tpid = aw!(insert_policy(&tinspol))?;

        let secid_uuid = Uuid::new_v4().as_hyphenated().to_string();
        let sec_uuid = Uuid::new_v4().as_hyphenated().to_string();

        aw!(insert_secret(
            &secid_uuid,
            &sec_uuid,
            Option::<u64>::Some(tpid)
        ))?;

        let testpol = aw!(get_secret_policy(&secid_uuid))?;

        assert_eq!(
            testpol.allowed_digests[0],
            "PuBT5e0dD21ZDoqdiBMNjWeKV2WhtcEOIdWeEsFwivw="
        );
        assert_eq!(testpol.allowed_policies[0], 0);
        assert_eq!(testpol.min_fw_api_major, 23);
        assert_eq!(testpol.min_fw_api_minor, 0);
        assert_eq!(testpol.allowed_build_ids[0], 0);

        Ok(())
    }

    #[test]
    fn test_secrets() -> anyhow::Result<()> {
        let secid = Uuid::new_v4().as_hyphenated().to_string();
        let sec = Uuid::new_v4().as_hyphenated().to_string();
        let polid = 0;
        aw!(insert_secret(&secid, &sec, Option::<u64>::Some(polid)))?;

        let tkey = aw!(get_secret(&secid))?;

        assert_eq!(tkey.id, secid);
        assert_eq!(tkey.payload, sec);

        aw!(delete_secret(&secid))?;
        Ok(())
    }

    #[test]
    fn test_insert_keyset() -> anyhow::Result<()> {
        let keys: Vec<String> = vec![
            "RGlyZSBXb2xmCg==".to_string(),
            "VGhlIFJhY2UgaXMgT24K".into(),
            "T2ggQmFiZSwgSXQgQWluJ3QgTm8gTGllCg==".into(),
            "SXQgTXVzdCBIYXZlIEJlZW4gdGhlIFJvc2VzCg==".into(),
            "RGFyayBIb2xsb3cK".into(),
            "Q2hpbmEgRG9sbAo=".into(),
            "QmVlbiBBbGwgQXJvdW5kIFRoaXMgV29ybGQK".into(),
            "TW9ua2V5IGFuZCB0aGUgRW5naW5lZXIK".into(),
            "SmFjay1BLVJvZQo=".into(),
            "RGVlcCBFbGVtIEJsdWVzCg==".into(),
            "Q2Fzc2lkeQo=".into(),
            "VG8gTGF5IE1lIERvd24K".into(),
            "Um9zYWxpZSBNY0ZhbGwK".into(),
            "T24gdGhlIFJvYWQgQWdhaW4K".into(),
            "QmlyZCBTb25nCg==".into(),
            "UmlwcGxlCg==".into(),
        ];

        let ksetid = Uuid::new_v4().as_hyphenated().to_string();
        let polid: Option<u32> = Some(1);
        aw!(insert_keyset(&ksetid, &keys, polid))?;

        let keyset_ids = aw!(get_keyset_ids(&ksetid))?;
        assert_eq!(keyset_ids.len(), keys.len());
        assert_eq!(keyset_ids, keys);

        aw!(delete_keyset(&ksetid))?;

        Ok(())
    }
}
