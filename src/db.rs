// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::policy;
use crate::request;

use anyhow::*;
use mysql::{OptsBuilder, Pool, PooledConn, TxOpts};
use std::env;
use std::result::Result::Ok;
use uuid::Uuid;

use mysql::prelude::*;

#[derive(Debug, Clone)]
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

pub fn get_dbconn() -> Result<PooledConn> {
    let host_name = env::var("KBS_DB_HOST").expect("KBS_DB_HOST not set");
    let user_name = env::var("KBS_DB_USER").expect("KBS_DB_USER not set.");
    let db_pw = env::var("KBS_DB_PW").expect("KBS_DB_PW not set.");
    let data_base = env::var("KBS_DB").expect("KBS_DB not set");

    let opts = OptsBuilder::new()
        .ip_or_hostname(Some(host_name))
        .user(Some(user_name))
        .pass(Some(db_pw))
        .db_name(Some(data_base));

    let dbpool = Pool::new(opts)?;
    let dbconn = dbpool.get_conn()?;
    Ok(dbconn)
}

pub fn insert_connection(connection: Connection) -> Result<Uuid> {
    let mut dbconn = get_dbconn()?;

    let nwuuid = Uuid::new_v4();
    let uuidstr = nwuuid.to_hyphenated().to_string();

    let mqstr = "INSERT INTO conn_bundle (id, policy, fw_api_major, fw_api_minor,
                 fw_build_id, launch_description, fw_digest,create_date)
                 VALUES(?, ?, ?, ?, ?, ?, ?,NOW())"
        .to_string();

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(
        mqstr,
        (
            uuidstr,
            connection.policy,
            connection.fw_api_major,
            connection.fw_api_minor,
            connection.fw_build_id,
            connection.launch_description,
            connection.fw_digest,
        ),
    )?;
    trnsx.commit()?;
    Ok(nwuuid)
}

pub fn insert_policy(policy: &policy::Policy) -> Result<u64> {
    let mut dbconn = get_dbconn()?;

    let allowed_digests_json = serde_json::to_string(&policy.allowed_digests)?;
    let allowed_policy_json = serde_json::to_string(&policy.allowed_policies)?;
    let allowed_build_ids_json = serde_json::to_string(&policy.allowed_build_ids)?;

    let mysqlstr = format!(
        "INSERT INTO policy (allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor,
                               allowed_build_ids, create_date, valid)
                               VALUES({:?}, {:?}, {}, {}, {:?}, NOW(), 1)",
        allowed_digests_json,
        allowed_policy_json,
        policy.min_fw_api_major,
        policy.min_fw_api_minor,
        allowed_build_ids_json
    );
    dbconn.query::<u64, String>(mysqlstr)?;
    Ok(dbconn.last_insert_id())
}

pub fn get_policy(pid: u64) -> Result<policy::Policy> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    let mqstr = "SELECT allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor, allowed_build_ids FROM policy WHERE id = ? AND valid = 1";
    let polval: Vec<(String, String, u32, u32, String)> = trnsx.exec(mqstr, (pid,))?;
    Ok(policy::Policy {
        allowed_digests: serde_json::from_str(&polval[0].0).unwrap(),
        allowed_policies: serde_json::from_str(&polval[0].1).unwrap(),
        min_fw_api_major: polval[0].2,
        min_fw_api_minor: polval[0].3,
        allowed_build_ids: serde_json::from_str(&polval[0].4).unwrap(),
    })
}

pub fn delete_policy(pid: &u64) -> Result<()> {
    let mut dbconn = get_dbconn()?;

    let mqstr = "DELETE from policy WHERE id = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;
    trnsx.exec_drop(mqstr, (&pid,))?;
    trnsx.commit()?;
    Ok(())
}

pub fn delete_connection(uuid: Uuid) -> Result<Uuid> {
    let mut dbconn = get_dbconn()?;

    let mqstr = "DELETE from conn_bundle WHERE id = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;
    trnsx.exec_drop(mqstr, (uuid.to_hyphenated().to_string(),))?;
    trnsx.commit()?;
    Ok(uuid)
}

pub fn get_connection(uuid: Uuid) -> Result<Connection> {
    let mut dbconn = get_dbconn()?;

    let uuidstr = uuid.to_hyphenated().to_string();
    let mqstr = "SELECT policy, fw_api_major, fw_api_minor, fw_build_id, launch_description, fw_digest FROM conn_bundle WHERE id = ?";

    let conres = dbconn.exec_map(
        mqstr,
        (uuidstr,),
        |(policy, fw_api_major, fw_api_minor, fw_build_id, launch_description, fw_digest)| {
            Connection {
                policy,
                fw_api_major,
                fw_api_minor,
                fw_build_id,
                launch_description,
                fw_digest,
            }
        },
    )?;

    Ok(conres[0].clone())
}

pub fn get_secret_policy(sec: &str) -> Option<policy::Policy> {
    let mut dbconn = get_dbconn().ok()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default()).ok()?;

    let mqstr = "SELECT polid FROM secrets WHERE secret_id = ?";

    let val_row: mysql::Row = trnsx.exec_first(mqstr, (sec,)).ok()?.unwrap();

    let val = mysql::from_value_opt::<u64>(val_row["polid"].clone()).ok()?;
    let secret_policy = get_policy(val).ok()?;
    Some(secret_policy)
}

pub fn insert_keyset(ksetid: &str, kskeys: &[String], polid: u32) -> Result<()> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    let mysqlstr = "INSERT INTO keysets (keysetid, kskeys, polid)
                    VALUES(?, ?, ?)"
        .to_string();

    /* create JSON for vector struct member variables */
    let kskeys_str = serde_json::to_string(kskeys)?;

    trnsx.exec_drop(mysqlstr, (ksetid, &kskeys_str, polid))?;
    trnsx.commit()?;
    Ok(())
}

pub fn delete_keyset(ksetid: &str) -> Result<()> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;
    let mysqlstr = "DELETE from keysets WHERE keysetid = ?".to_string();

    /* create JSON for vector struct member variables */

    trnsx.exec_drop(mysqlstr, (ksetid,))?;
    trnsx.commit()?;
    Ok(())
}

pub fn get_keyset_policy(keysetid: &str) -> Result<policy::Policy> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    let mqstr = "SELECT polid FROM keysets WHERE keysetid = ?";

    let keyset_policy_opt: Option<u64> = trnsx.exec_first(mqstr, (keysetid,))?;
    let keyset_policy_id = keyset_policy_opt
        .ok_or_else(|| anyhow!("db::get_keyset_policy- error no policy id for keyset_id"))?;

    let retpol = get_policy(keyset_policy_id)?;

    Ok(retpol)
}

// A keyset is just a group of keys. This function returns a vector of key ids for secrets in table secrets
pub fn get_keyset_ids(keysetid: &str) -> Result<Vec<String>> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    let mqstr = "SELECT kskeys FROM keysets WHERE keysetid = ?";
    let keyset_json_opt: Option<String> = trnsx.exec_first(mqstr, (keysetid,))?;
    let keyset_json_str =
        keyset_json_opt.ok_or_else(|| anyhow!("db::get_keyset_ids- keyset id not found"))?;

    let rks: Vec<String> = serde_json::from_str(&keyset_json_str).unwrap();

    Ok(rks)
}

pub fn get_secret(secret_id: &str) -> Result<request::Key> {
    let mut dbconn = get_dbconn()?;
    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    let mqstr = "SELECT secret FROM secrets WHERE secret_id = ?";
    let val: Option<String> = trnsx.exec_first(mqstr, (secret_id,))?;

    let payload = val.ok_or_else(|| anyhow!("secret not found."))?;

    Ok(request::Key {
        id: secret_id.to_string(),
        payload,
    })
}

pub fn insert_secret(secret_id: &str, secret: &str, policy_id: u64) -> Result<()> {
    let mut dbconn = get_dbconn()?;

    let mqstr = "INSERT INTO secrets (secret_id, secret, polid ) VALUES(?, ?, ?)";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (&secret_id, &secret, &policy_id))?;
    trnsx.commit()?;
    Ok(())
}

pub fn insert_secret_only(secret_id: &str, secret: &str) -> Result<()> {
    let mut dbconn = get_dbconn()?;

    let mqstr = "INSERT INTO secrets (secret_id, secret) VALUES(?, ?)";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (&secret_id, &secret))?;
    trnsx.commit()?;
    Ok(())
}

pub fn delete_secret(secret_id: &str) -> Result<()> {
    let mut dbconn = get_dbconn()?;

    let mqstr = "DELETE from secrets WHERE secret_id = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (secret_id,))?;
    trnsx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection() -> anyhow::Result<()> {
        let testconn = Connection::default();

        let tid = insert_connection(testconn.clone())?;

        let resconn = get_connection(tid.clone())?;

        assert_eq!(testconn.policy, resconn.policy);
        assert_eq!(testconn.fw_api_major, resconn.fw_api_major);
        assert_eq!(testconn.fw_api_minor, resconn.fw_api_minor);
        assert_eq!(testconn.fw_build_id, resconn.fw_build_id);
        assert_eq!(testconn.launch_description, resconn.launch_description);
        let _dconid = delete_connection(tid.clone());

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

        let polid = insert_policy(&testpol)?;

        let rpol = get_policy(polid)?;

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

        delete_policy(&polid)?;
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

        let tpid = insert_policy(&tinspol)?;

        let secid_uuid = Uuid::new_v4().to_hyphenated().to_string();
        let sec_uuid = Uuid::new_v4().to_hyphenated().to_string();

        insert_secret(&secid_uuid, &sec_uuid, tpid)?;

        let testpol = get_secret_policy(&secid_uuid)
            .ok_or(anyhow!("db::test_secret_policy- no policy returned"))?;

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
        let secid = Uuid::new_v4().to_hyphenated().to_string();
        let sec = Uuid::new_v4().to_hyphenated().to_string();
        let polid = 0;
        insert_secret(&secid, &sec, polid)?;

        let tkey = get_secret(&secid)?;

        assert_eq!(tkey.id, secid);
        assert_eq!(tkey.payload, sec);

        delete_secret(&secid)?;
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

        let ksetid = Uuid::new_v4().to_hyphenated().to_string();
        let polid = 1;
        insert_keyset(&ksetid, &keys, polid)?;
        let keyset_ids = get_keyset_ids(&ksetid)?;
        assert_eq!(keyset_ids.len(), keys.len());
        assert_eq!(keyset_ids, keys);
        Ok(())
    }
}
