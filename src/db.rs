// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::policy;
use crate::request;

use anyhow::*;
use log::*;
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

pub fn get_dbconn() -> mysql::Result<PooledConn> {
    let host_name = env::var("KBS_DB_HOST").expect("KBS_DB_HOST not set");
    let user_name = env::var("KBS_DB_USER").expect("KBS_DB_USER not set.");
    let db_pw = env::var("KBS_DB_PW").expect("KBS_DB_PW not set.");
    let data_base = env::var("KBS_DB").expect("KBS_DB not set");

    let opts = OptsBuilder::new()
        .ip_or_hostname(Some(host_name))
        .user(Some(user_name))
        .pass(Some(db_pw))
        .db_name(Some(data_base));

    let dbpool = Pool::new(opts).unwrap();
    let dbconn = dbpool.get_conn().unwrap();

    Ok(dbconn)
}

pub fn insert_connection(connection: Connection) -> Result<Uuid> {
    let mut dbconn = get_dbconn().unwrap();

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

pub fn delete_connection(uuid: Uuid) -> Result<Uuid> {
    let mut dbconn = get_dbconn().unwrap();

    let mqstr = "DELETE from conn_bundle WHERE id = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;
    trnsx.exec_drop(mqstr, (uuid.to_hyphenated().to_string(),))?;
    trnsx.commit()?;
    Ok(uuid)
}

pub fn get_connection(uuid: Uuid) -> Result<Connection> {
    let mut dbconn = get_dbconn().unwrap();

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
    let mut dbconn = get_dbconn().unwrap();
    let mut trnsx = dbconn.start_transaction(TxOpts::default()).ok()?;

    let mqstr = "SELECT polids FROM secpol WHERE secret = ?";

    let val: Option<i32> = trnsx.exec_first(mqstr, (sec,)).ok()?;

    if val.is_none() {
        error!(
            "get_secret_policy::error cannot get policy id with secret {}",
            &sec
        );
        return None;
    }

    let mqstr = "SELECT allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor, allowed_build_ids FROM policy WHERE id = ?";

    let polval: Vec<(String, String, u32, u32, String)> = trnsx.exec(mqstr, (val,)).ok()?;

    Some(policy::Policy {
        allowed_digests: serde_json::from_str(&polval[0].0).unwrap(),
        allowed_policies: serde_json::from_str(&polval[0].1).unwrap(),
        min_fw_api_major: polval[0].2,
        min_fw_api_minor: polval[0].3,
        allowed_build_ids: serde_json::from_str(&polval[0].4).unwrap(),
    })
}

pub fn insert_polid(sec: &str, polid: u32) -> Result<u32> {
    let mut dbconn = get_dbconn().unwrap();

    let mqstr = "INSERT INTO secpol (secret, polids ) VALUES(?, ?)".to_string();

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (&sec, &polid))?;
    trnsx.commit()?;
    Ok(polid)
}

pub fn delete_polid(sec: &str) -> Result<String> {
    let mut dbconn = get_dbconn().unwrap();

    let mqstr = "DELETE from secpol WHERE secret = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (&sec,))?;
    trnsx.commit()?;
    Ok(sec.to_string())
}

pub fn get_keyset_policy(_secset: &str) -> Option<policy::Policy> {
    None
}

// A keyset is just a group of keys.
pub fn get_keyset_ids(_id: &str) -> Result<Vec<String>> {
    Ok(vec!["keyid-1".to_string()])
}

// Get the secret from the secret id. In the future we should
// support external keyvaults rather than just storing the key
// in the table.
//
// The key struct is in request.rs. Secret payload should
// be a string.
pub fn get_secret(id: &str) -> Option<request::Key> {
    let mut dbconn = get_dbconn().unwrap();
    let mut trnsx = dbconn.start_transaction(TxOpts::default()).ok()?;

    let mqstr = "SELECT secret FROM secrets WHERE secret_id = ?";
    let val: Option<String> = trnsx.exec_first(mqstr, (id,)).ok()?;

    Some(request::Key {
        id: id.to_string(),
        payload: val.unwrap(),
    })
}

pub fn insert_secret(id: &str, sec: &str, polid: u32) -> Result<String> {
    let mut dbconn = get_dbconn().unwrap();

    let mqstr = "INSERT INTO secrets (secret_id, secret, polid ) VALUES(?, ?, ?)";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (&id, &sec, &polid))?;
    trnsx.commit()?;
    Ok(id.to_string())
}

pub fn delete_secret(id: &str) -> Result<String> {
    let mut dbconn = get_dbconn().unwrap();

    let mqstr = "DELETE from secrets WHERE secret_id = ?";

    let mut trnsx = dbconn.start_transaction(TxOpts::default())?;

    trnsx.exec_drop(mqstr, (id,))?;
    trnsx.commit()?;
    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection() {
        let testconn = Connection::default();

        let tid = insert_connection(testconn.clone()).unwrap();

        let resconn = get_connection(tid).unwrap();

        assert_eq!(testconn.policy, resconn.policy);
        assert_eq!(testconn.fw_api_major, resconn.fw_api_major);
        assert_eq!(testconn.fw_api_minor, resconn.fw_api_minor);
        assert_eq!(testconn.fw_build_id, resconn.fw_build_id);
        assert_eq!(testconn.launch_description, resconn.launch_description);

        let _delcon = delete_connection(tid);
    }

    #[test]
    fn test_policy() {
        let sec = "LXItLS4gIDEgcm9vdCByb290ICAxNzMgQXVnIDMwIDA2OjQ2IC52bWxpbnV6LTQuMTguMC0zMDUuMTcuMS5lbDhfNC54ODZfNjQuaG1hYwo=".to_string();
        let tpid = 1;

        let polid = insert_polid(&sec, tpid).unwrap();

        let testpol = get_secret_policy(&sec).unwrap();

        assert_eq!(
            testpol.allowed_digests[0],
            "PuBT5e0dD21ZDoqdiBMNjWeKV2WhtcEOIdWeEsFwivw="
        );
        assert_eq!(testpol.allowed_policies[0], 0);
        assert_eq!(testpol.min_fw_api_major, 23);
        assert_eq!(testpol.min_fw_api_minor, 0);
        assert_eq!(testpol.allowed_build_ids[0], 10);

        let _delsec = delete_polid(&sec).unwrap();
    }

    #[test]
    fn test_secrets() {
        let secid = "talking-donkies-can-fly".to_string();
        let sec = "LXItLS4gIDEgcm9vdCByb290ICAxNzMgQXVnIDMwIDA2OjQ2IC52bWxpbnV6LTQuMTguMC0zMDUuMTcuMS5lbDhfNC54ODZfNjQuaG1hYwo=".to_string();
        let polid = 0;
        let _insecid = insert_secret(&secid, &sec, polid).unwrap();

        let tkey = get_secret(&secid).unwrap();

        assert_eq!(tkey.id, secid);
        assert_eq!(tkey.payload, sec);

        let _dsecid = delete_secret(&secid).unwrap();
    }
}
