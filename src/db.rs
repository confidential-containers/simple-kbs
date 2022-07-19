// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::policy;
use crate::request;

use anyhow::*;
use std::env;
use std::result::Result::Ok;
use uuid::Uuid;

use log::*;
use regex::{Captures, Regex, RegexSet};
use serde::{Deserialize, Serialize};
use sqlx::any::{AnyKind, AnyPoolOptions};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::postgres::PgRow;
use sqlx::AnyPool;
use sqlx::MySqlPool;
use sqlx::PgPool;
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

/// check_input is meant to check string fields that are passed to db functions to input or get
/// data required for simple-kbs functions.  It will check for common sql injection attacks in
/// variables passed and log suspect strings to central logging facilities returning false.  If a
/// string passes our checks, check_input returns true.
pub fn check_input(field: String) -> bool {
    let str_check = field.to_lowercase();
    let check_set = RegexSet::new(&[
        r"[']{0,}1[']{0,}\s{0,}=\s{0,}[']{0,}1[']{0,}",
        r"drop",
        r"select\s{0,}[*]",
        r"user",
        r"password",
        r"alter",
        r"delete",
    ])
    .unwrap();
    let check_matches: Vec<_> = check_set.matches(&str_check).into_iter().collect();

    if !check_matches.is_empty() {
        for match_num in check_matches.iter() {
            match match_num {
                0 => error!("db::check_input - found 1 = 1 statement in input"),
                1 => error!("db::check_input - found drop statement in input"),
                2 => error!("db::check_input - found select statement in input"),
                3 => error!("db::check_input - found user statement in input"),
                4 => error!("db::check_input - found password statement in input"),
                5 => error!("db::check_input - found alter statement in input"),
                6 => error!("db::check_input - found delete statement in input"),
                _ => error!("db::check_input - found uncharacterized statement in input"),
            };
        }
        false
    } else {
        true
    }
}

pub async fn get_dbpool() -> Result<AnyPool> {
    let db_type = env::var("KBS_DB_TYPE").expect("KBS_DB_TYPE not set");
    let host_name = env::var("KBS_DB_HOST").expect("KBS_DB_HOST not set");
    let user_name = env::var("KBS_DB_USER").expect("KBS_DB_USER not set.");
    let db_pw = env::var("KBS_DB_PW").expect("KBS_DB_PW not set.");
    let data_base = env::var("KBS_DB").expect("KBS_DB not set");

    if !check_input(db_type.to_string())
        || !check_input(host_name.to_string())
        || !check_input(user_name.to_string())
        || !check_input(db_pw.to_string())
        || !check_input(data_base.to_string())
    {
        error!("db::get_dbpool- env vars db_type, host_name, user_name, db_pw, or database did not pass sql injection check");
        return Err(anyhow!("db::get_dbpool- env vars db_type, host_name, user_name, db_pw, or database did not pass sql injection check"));
    }

    let db_url = format!(
        "{}://{}:{}@{}/{}",
        db_type, user_name, db_pw, host_name, data_base
    );

    let db_pool = AnyPoolOptions::new()
        .max_connections(1000)
        .connect(&db_url)
        .await
        .map_err(|e| {
            anyhow!(
                "db::get_db_pool:: Encountered error trying to create database pool: {}",
                e
            )
        })?;
    Ok(db_pool)
}

pub async fn get_mysql_dbpool() -> Result<MySqlPool> {
    let db_type = env::var("KBS_DB_TYPE").expect("KBS_DB_TYPE not set");
    let host_name = env::var("KBS_DB_HOST").expect("KBS_DB_HOST not set");
    let user_name = env::var("KBS_DB_USER").expect("KBS_DB_USER not set.");
    let db_pw = env::var("KBS_DB_PW").expect("KBS_DB_PW not set.");
    let data_base = env::var("KBS_DB").expect("KBS_DB not set");

    if !check_input(db_type.to_string())
        || !check_input(host_name.to_string())
        || !check_input(user_name.to_string())
        || !check_input(db_pw.to_string())
        || !check_input(data_base.to_string())
    {
        error!("db::get_mysql_dbpool- env vars db_type, host_name, user_name, db_pw, or database did not pass sql injection check");
        return Err(anyhow!("db::get_mysql_dbpool- env vars db_type, host_name, user_name, db_pw, or database did not pass sql injection check"));
    }

    let db_url = format!(
        "{}://{}:{}@{}/{}",
        db_type, user_name, db_pw, host_name, data_base
    );

    let db_pool = MySqlPoolOptions::new()
        .max_connections(1000)
        .connect(&db_url)
        .await
        .map_err(|e| {
            anyhow!(
                "db::get_mysql_dbpool - Encountered error trying to create database pool: {}",
                e
            )
        })?;
    Ok(db_pool)
}

pub async fn get_postgres_dbpool() -> Result<PgPool> {
    let db_type = env::var("KBS_DB_TYPE").expect("KBS_DB_TYPE not set");
    let host_name = env::var("KBS_DB_HOST").expect("KBS_DB_HOST not set");
    let user_name = env::var("KBS_DB_USER").expect("KBS_DB_USER not set.");
    let db_pw = env::var("KBS_DB_PW").expect("KBS_DB_PW not set.");
    let data_base = env::var("KBS_DB").expect("KBS_DB not set");

    if !check_input(db_type.to_string())
        || !check_input(host_name.to_string())
        || !check_input(user_name.to_string())
        || !check_input(db_pw.to_string())
        || !check_input(data_base.to_string())
    {
        error!("db::get_postgres_dbpool- env vars db_type, host_name, user_name, db_pw, or database did not pass sql injection check");
        return Err(anyhow!("db::get_postgres_dbpool- env vars db_type, host_name, user_name, db_pw, or database did not pass sql injection check"));
    }

    let db_url = format!(
        "{}://{}:{}@{}/{}",
        db_type, user_name, db_pw, host_name, data_base
    );

    let db_pool = PgPoolOptions::new()
        .max_connections(1000)
        .connect(&db_url)
        .await
        .map_err(|e| {
            anyhow!(
                "db::get_mysql_dbpool - Encountered error trying to create database pool: {}",
                e
            )
        })?;
    Ok(db_pool)
}

fn replace_binds(kind: AnyKind, sql: &str) -> String {
    if kind != AnyKind::Postgres {
        return sql.to_string();
    }

    // Replace question marks by $1, $2, ...
    let question_mark_re = Regex::new(r"\?").unwrap();
    let mut counter = 0;
    let result = question_mark_re.replace_all(sql, |_: &Captures| {
        counter += 1;
        format!("${}", counter)
    });
    result.to_string()
}

pub async fn insert_connection(connection: Connection) -> Result<Uuid> {
    let nwuuid = Uuid::new_v4();
    let uuidstr = nwuuid.as_hyphenated().to_string();

    let dbpool = get_dbpool().await?;

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();
    let query_str = "INSERT INTO conn_bundle (id, policy, fw_api_major, fw_api_minor, fw_build_id, launch_description, fw_digest, create_date) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())";
    let new_query_str: String = if db_type == *"postgres" {
        replace_binds(dbpool.any_kind(), query_str)
    } else {
        query_str.to_string()
    };

    sqlx::query(&new_query_str.to_string())
        .bind(uuidstr)
        .bind(connection.policy as i64)
        .bind(connection.fw_api_major as i64)
        .bind(connection.fw_api_minor as i64)
        .bind(connection.fw_build_id as i64)
        .bind(&connection.launch_description)
        .bind(&connection.fw_digest)
        .execute(&dbpool)
        .await?;
    Ok(nwuuid)
}

pub async fn get_connection(uuid: Uuid) -> Result<Connection> {
    let uuidstr = uuid.as_hyphenated().to_string();

    let dbpool = get_dbpool().await?;

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();
    let query_str = "SELECT policy, fw_api_major, fw_api_minor, fw_build_id, launch_description, fw_digest FROM conn_bundle WHERE id = ?";
    let new_query_str: String = if db_type == *"postgres" {
        replace_binds(dbpool.any_kind(), query_str)
    } else {
        query_str.to_string()
    };

    let con_row = sqlx::query(&new_query_str.to_string())
        .bind(uuidstr)
        .fetch_one(&dbpool)
        .await?;
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
    let uuidstr = uuid.as_hyphenated().to_string();

    let dbpool = get_dbpool().await?;

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();
    let query_str = "DELETE from conn_bundle WHERE id = ?";
    let new_query_str: String = if db_type == *"postgres" {
        replace_binds(dbpool.any_kind(), query_str)
    } else {
        query_str.to_string()
    };

    sqlx::query(&new_query_str.to_string())
        .bind(uuidstr)
        .execute(&dbpool)
        .await?;
    Ok(uuid)
}

pub async fn insert_policy(policy: &policy::Policy) -> Result<u64> {
    let allowed_digests_json = serde_json::to_string(&policy.allowed_digests)?;
    let allowed_policies_json = serde_json::to_string(&policy.allowed_policies)?;
    let allowed_build_ids_json = serde_json::to_string(&policy.allowed_build_ids)?;

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();
    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let last_insert_row = sqlx::query("INSERT INTO policy (allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor, allowed_build_ids, create_date, valid) VALUES(?, ?, ?, ?, ?, NOW(), 1)")
                .bind(allowed_digests_json)
                .bind(allowed_policies_json)
                .bind(policy.min_fw_api_major)
                .bind(policy.min_fw_api_minor)
                .bind(allowed_build_ids_json)
                .execute(&dbpool)
                .await?
                .last_insert_id();

            Ok(last_insert_row)
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let last_insert_row = sqlx::query("insert into conn_bundle (id, policy, fw_api_major, fw_api_minor, fw_build_id, launch_description, fw_digest, create_date) VALUES($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING id")
                .bind(allowed_digests_json)
                .bind(allowed_policies_json)
                .bind(policy.min_fw_api_major)
                .bind(policy.min_fw_api_minor)
                .bind(allowed_build_ids_json)
                .try_map(| row: PgRow | row.try_get::<i64, _>(0))
                .fetch_one(&dbpool)
                .await?;

            Ok(last_insert_row as u64)
        }
        _ => {
            error!(
                "db::insert_connection- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::insert_connection- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn get_policy(pid: u64) -> Result<policy::Policy> {
    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let row_vec =
                sqlx::query("SELECT allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor, allowed_build_ids FROM policy WHERE id = ? AND valid = 1")
                .bind(pid)
                .fetch_one(&dbpool)
                .await?;
            Ok(policy::Policy {
                allowed_digests: serde_json::from_str(&row_vec.try_get::<String, _>(0)?)?,
                allowed_policies: serde_json::from_str(&row_vec.try_get::<String, _>(1)?)?,
                min_fw_api_major: row_vec.try_get::<i32, _>(2)? as u32,
                min_fw_api_minor: row_vec.try_get::<i32, _>(3)? as u32,
                allowed_build_ids: serde_json::from_str(&row_vec.try_get::<String, _>(4)?)?,
            })
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let row_vec =
                sqlx::query("SELECT allowed_digests, allowed_policies, min_fw_api_major, min_fw_api_minor, allowed_build_ids FROM policy WHERE id = $1 AND valid = 1")
                .bind(pid as i64)
                .fetch_one(&dbpool)
                .await?;
            Ok(policy::Policy {
                allowed_digests: serde_json::from_str(&row_vec.try_get::<String, _>(0)?)?,
                allowed_policies: serde_json::from_str(&row_vec.try_get::<String, _>(1)?)?,
                min_fw_api_major: row_vec.try_get::<i32, _>(2)? as u32,
                min_fw_api_minor: row_vec.try_get::<i32, _>(3)? as u32,
                allowed_build_ids: serde_json::from_str(&row_vec.try_get::<String, _>(4)?)?,
            })
        }
        _ => {
            error!(
                "db::insert_connection- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::insert_connection- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn delete_policy(pid: &u64) -> Result<()> {
    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            sqlx::query("DELETE from policy WHERE id = ?")
                .bind(pid)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            sqlx::query("DELETE from policy WHERE id = $1")
                .bind(*pid as i64)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        _ => {
            error!(
                "db::delete_connection- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::delete_connection- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn get_secret_policy(sec: &str) -> Result<policy::Policy> {
    if !check_input(sec.to_string()) {
        error!("db::get_secret_policy- field sec did not pass sql injection check");
        return Err(anyhow!(
            "db::get_secret_policy- field sec did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let pol_row = sqlx::query("SELECT polid FROM secrets WHERE secret_id = ?")
                .bind(sec)
                .fetch_one(&dbpool)
                .await?;
            let pol = pol_row.try_get::<i32, _>(0)? as u64;
            let secret_policy = get_policy(pol).await?;
            Ok(secret_policy)
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let pol_row = sqlx::query("SELECT polid FROM secrets WHERE secret_id = $1")
                .bind(sec)
                .fetch_one(&dbpool)
                .await?;
            let pol = pol_row.try_get::<i32, _>(0)? as u64;
            let secret_policy = get_policy(pol).await?;
            Ok(secret_policy)
        }
        _ => {
            error!(
                "db::get_secret_policy- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::get_secret_policy- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn insert_keyset(ksetid: &str, kskeys: &[String], polid: Option<u32>) -> Result<()> {
    let kskeys_str = serde_json::to_string(kskeys)?;

    if !check_input(ksetid.to_string()) || !check_input(kskeys_str.clone()) {
        error!("db::insert_keyset- json fields passed to insert_policy did not pass sql injection check");
        return Err(anyhow!("db::insert_keyset- json fields passed to insert_policy did not pass sql injection check"));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();
    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            match polid {
                Some(p) => {
                    sqlx::query("INSERT INTO keysets (keysetid, kskeys, polid) VALUES(?, ?, ?)")
                        .bind(ksetid)
                        .bind(&kskeys_str)
                        .bind(p)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
                None => {
                    sqlx::query("INSERT INTO keysets (keysetid, kskeys) VALUES(?, ?)")
                        .bind(ksetid)
                        .bind(&kskeys_str)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
            }
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            match polid {
                Some(p) => {
                    sqlx::query("INSERT INTO keysets (keysetid, kskeys, polid) VALUES($1, $2, $3)")
                        .bind(ksetid)
                        .bind(&kskeys_str)
                        .bind(p)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
                None => {
                    sqlx::query("INSERT INTO keysets (keysetid, kskeys) VALUES($1, $2)")
                        .bind(ksetid)
                        .bind(&kskeys_str)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
            }
        }
        _ => {
            error!("db::insert_keyset- error, this is not a mysql, sqlite, or postgres connection");
            Err(anyhow!(
                "db::insert_keyset- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn delete_keyset(ksetid: &str) -> Result<()> {
    if !check_input(ksetid.to_string()) {
        error!("db::delete_keyset- json fields passed to delete_keyset did not pass sql injection check");
        return Err(anyhow!("db::delete_keyset- json fields passed to delete_keyset did not pass sql injection check"));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            sqlx::query("DELETE from keysets WHERE keysetid = ?")
                .bind(ksetid)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            sqlx::query("DELETE from keysets WHERE keysetid = $1")
                .bind(ksetid)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        _ => {
            error!("db::delete_keyset- error, this is not a mysql, sqlite, or postgres connection");
            Err(anyhow!(
                "db::delete_keyset- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn get_keyset_policy(keysetid: &str) -> Result<policy::Policy> {
    if !check_input(keysetid.to_string()) {
        error!("db::get_keyset_policy- field sec did not pass sql injection check");
        return Err(anyhow!(
            "db::get_keyset_policy- field sec did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let pol_row = sqlx::query("SELECT polid FROM keysets WHERE keysetid = ?")
                .bind(keysetid)
                .fetch_one(&dbpool)
                .await?;
            let pol = pol_row.try_get::<i32, _>(0)? as u64;
            let secret_policy = get_policy(pol).await?;
            Ok(secret_policy)
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let pol_row = sqlx::query("SELECT polid FROM secrets WHERE keysetid = $1")
                .bind(keysetid)
                .fetch_one(&dbpool)
                .await?;
            let pol = pol_row.try_get::<i32, _>(0)? as u64;
            let secret_policy = get_policy(pol).await?;
            Ok(secret_policy)
        }
        _ => {
            error!(
                "db::get_secret_policy- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::get_secret_policy- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn get_keyset_ids(keysetid: &str) -> Result<Vec<String>> {
    if !check_input(keysetid.to_string()) {
        error!("db::get_keyset_ids- field sec did not pass sql injection check");
        return Err(anyhow!(
            "db::get_keyset_ids- field sec did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let keyset_row = sqlx::query("SELECT kskeys FROM keysets WHERE keysetid = ?")
                .bind(keysetid)
                .fetch_one(&dbpool)
                .await?;
            let rks: Vec<String> =
                serde_json::from_str(&keyset_row.try_get::<String, _>(0)?).unwrap();
            Ok(rks)
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let keyset_row = sqlx::query("SELECT kskeys FROM keysets WHERE keysetid = $1")
                .bind(keysetid)
                .fetch_one(&dbpool)
                .await?;
            let rks: Vec<String> =
                serde_json::from_str(&keyset_row.try_get::<String, _>(0)?).unwrap();
            Ok(rks)
        }
        _ => {
            error!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn get_secret(secret_id: &str) -> Result<request::Key> {
    if !check_input(secret_id.to_string()) {
        error!("db::get_secret- field sec did not pass sql injection check");
        return Err(anyhow!(
            "db::get_secret- field sec did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let secret_row = sqlx::query("SELECT secret FROM secrets WHERE secret_id = ?")
                .bind(secret_id)
                .fetch_one(&dbpool)
                .await?;
            let secret = secret_row.try_get::<String, _>(0)?;
            Ok(request::Key {
                id: secret_id.to_string(),
                payload: secret,
            })
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let secret_row = sqlx::query("SELECT secret FROM secrets WHERE secret_id = $1")
                .bind(secret_id)
                .fetch_one(&dbpool)
                .await?;
            let secret = secret_row.try_get::<String, _>(0)?;
            Ok(request::Key {
                id: secret_id.to_string(),
                payload: secret,
            })
        }
        _ => {
            error!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn insert_secret(secret_id: &str, secret: &str, policy_id: Option<u64>) -> Result<()> {
    if !check_input(secret_id.to_string()) || !check_input(secret.to_string()) {
        error!(
            "db::insert_secret- fields passed to insert_secret did not pass sql injection check"
        );
        return Err(anyhow!(
            "db::insert_secret- fields passed to insert_secret did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();
    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            match policy_id {
                Some(p) => {
                    sqlx::query("INSERT INTO secrets (secret_id, secret, polid ) VALUES(?, ?, ?)")
                        .bind(secret_id)
                        .bind(secret)
                        .bind(p)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
                None => {
                    sqlx::query("INSERT INTO secrets (secret_id, secret) VALUES(?, ?)")
                        .bind(secret_id)
                        .bind(secret)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
            }
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            match policy_id {
                Some(p) => {
                    sqlx::query(
                        "INSERT INTO secrets (secret_id, secret, polid) VALUES($1, $2, $3)",
                    )
                    .bind(secret_id)
                    .bind(&secret)
                    .bind(p as i64)
                    .execute(&dbpool)
                    .await?;
                    Ok(())
                }
                None => {
                    sqlx::query("INSERT INTO keysets (secret_id, secret) VALUES($1, $2)")
                        .bind(secret_id)
                        .bind(secret)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
            }
        }
        _ => {
            error!("db::insert_secret- error, this is not a mysql, sqlite, or postgres connection");
            Err(anyhow!(
                "db::insert_secret- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn delete_secret(secret_id: &str) -> Result<()> {
    if !check_input(secret_id.to_string()) {
        error!(
            "db::delete_secret- fields passed to delete_secret did not pass sql injection check"
        );
        return Err(anyhow!(
            "db::delete_secret- fields passed to delete_keyset did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            sqlx::query("DELETE from secrets WHERE secret_id = ?")
                .bind(secret_id)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            sqlx::query("DELETE from secrets WHERE secret_id = $1")
                .bind(secret_id)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        _ => {
            error!("db::delete_secret- error, this is not a mysql, sqlite, or postgres connection");
            Err(anyhow!(
                "db::delete_secret- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

// ------------------------------------------------------------------------------------

pub async fn insert_report_keypair(id: &str, keypair: &[u8], policy_id: Option<u64>) -> Result<()> {
    if !check_input(id.to_string()) {
        error!(
            "db::insert_report_keypair- field passed to insert_secret did not pass sql injection check"
        );
        return Err(anyhow!(
            "db::insert_report_keypair- field passed to insert_secret did not pass sql injection check"
        ));
    }
    let keypair_b64 = base64::encode(&keypair);
    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();
    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            match policy_id {
                Some(p) => {
                    sqlx::query(
                        "INSERT INTO report_keypair (key_id, keypair, polid) VALUES(?, ?, ?)",
                    )
                    .bind(id)
                    .bind(keypair_b64)
                    .bind(p)
                    .execute(&dbpool)
                    .await?;
                    Ok(())
                }
                None => {
                    sqlx::query("INSERT INTO report_keypair (key_id, keypair) VALUES(?, ?)")
                        .bind(id)
                        .bind(keypair_b64)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
            }
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            match policy_id {
                Some(p) => {
                    sqlx::query(
                        "INSERT INTO report_keypair (key_id, keypair, p) VALUES($1, $2, $3)",
                    )
                    .bind(id)
                    .bind(keypair_b64)
                    .bind(p as i64)
                    .execute(&dbpool)
                    .await?;
                    Ok(())
                }
                None => {
                    sqlx::query("INSERT INTO report_keypair (key_id, keypair) VALUES($1, $2)")
                        .bind(id)
                        .bind(keypair_b64)
                        .execute(&dbpool)
                        .await?;
                    Ok(())
                }
            }
        }
        _ => {
            error!("db::insert_report_keypair- error, this is not a mysql, sqlite, or postgres connection");
            Err(anyhow!(
                "db::insert_report_keypair- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn get_report_keypair(id: &str) -> Result<Vec<u8>> {
    if !check_input(id.to_string()) {
        error!("db::get_report_keypair- field sec did not pass sql injection check");
        return Err(anyhow!(
            "db::get_report_keypair- field sec did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let key_row = sqlx::query("SELECT keypair FROM report_keypair WHERE key_id = ?")
                .bind(id)
                .fetch_one(&dbpool)
                .await?;
            let kp = key_row.try_get::<String, _>(0)?;
            let kp_bytes = base64::decode(&kp)?;
            Ok(kp_bytes)
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let key_row = sqlx::query("SELECT secret FROM secrets WHERE secret_id = $1")
                .bind(id)
                .fetch_one(&dbpool)
                .await?;
            let kp = key_row.try_get::<String, _>(0)?;
            let kp_bytes = base64::decode(&kp)?;
            Ok(kp_bytes)
        }
        _ => {
            error!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn delete_report_keypair(key_id: &str) -> Result<()> {
    if !check_input(key_id.to_string()) {
        error!(
            "db::delete_report_keypair- fields passed to delete_secret did not pass sql injection check"
        );
        return Err(anyhow!(
            "db::delete_report_keypair- fields passed to delete_keyset did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            sqlx::query("DELETE from report_keypair WHERE key_id = ?")
                .bind(key_id)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            sqlx::query("DELETE from report_keypair WHERE key_id = $1")
                .bind(key_id)
                .execute(&dbpool)
                .await?;
            Ok(())
        }
        _ => {
            error!("db::delete_report_keypair- error, this is not a mysql, sqlite, or postgres connection");
            Err(anyhow!(
                "db::delete_report_keypair- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

pub async fn get_signing_keys_policy(key_id: &str) -> Result<Option<policy::Policy>> {
    if !check_input(key_id.to_string()) {
        error!("db::get_signing_keys_policy- field sec did not pass sql injection check");
        return Err(anyhow!(
            "db::get_signing_keys_policy- field sec did not pass sql injection check"
        ));
    }

    let db_type = env::var("KBS_DB_TYPE")
        .expect("KBS_DB_TYPE not set")
        .to_lowercase();

    match db_type.as_str() {
        "mysql" | "sqlite" => {
            let dbpool = get_mysql_dbpool().await?;
            let policy_id_option = sqlx::query(
                "SELECT polid FROM report_keypair WHERE key_id = ? AND polid IS NOT NULL",
            )
            .bind(key_id)
            .fetch_optional(&dbpool)
            .await?;
            match policy_id_option {
                Some(p) => {
                    let pid = p.try_get::<i64, _>(0)? as u64;
                    Ok(Some(get_policy(pid).await?))
                }
                None => Ok(None),
            }
        }
        "postgres" => {
            let dbpool = get_postgres_dbpool().await?;
            let policy_id_option = sqlx::query(
                "SELECT polid FROM report_keypair WHERE key_id = $1 AND polid IS NOT NULL",
            )
            .bind(key_id)
            .fetch_optional(&dbpool)
            .await?;
            match policy_id_option {
                Some(p) => {
                    let pid = p.try_get::<i64, _>(0)? as u64;
                    Ok(Some(get_policy(pid).await?))
                }
                None => Ok(None),
            }
        }
        _ => {
            error!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            );
            Err(anyhow!(
                "db::get_keyset_ids- error, this is not a mysql, sqlite, or postgres connection"
            ))
        }
    }
}

// -----------------------------------------------------------------------------------
#[cfg(test)]
mod tests {

    use super::*;
    use ring::{rand::SystemRandom, signature};

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
    fn test_check_input() -> anyhow::Result<()> {
        let mut test_string = r"'1'='1'";
        let mut ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"1 = 1";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"drop";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"select *";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"user";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"password";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"alter";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"delete";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, false);

        test_string = r"PuBT5e0dD21ZDoqdiBMNjWeKV2WhtcEOIdWeEsFwivw=";
        ret = check_input(test_string.to_string());
        assert_eq!(ret, true);

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

        aw!(insert_secret(&secid_uuid, &sec_uuid, Option::Some(tpid)))?;

        let testpol = aw!(get_secret_policy(&secid_uuid))?;

        assert_eq!(
            testpol.allowed_digests[0],
            "PuBT5e0dD21ZDoqdiBMNjWeKV2WhtcEOIdWeEsFwivw="
        );
        assert_eq!(testpol.allowed_policies[0], 0);
        assert_eq!(testpol.min_fw_api_major, 23);
        assert_eq!(testpol.min_fw_api_minor, 0);
        assert_eq!(testpol.allowed_build_ids[0], 0);

        aw!(delete_secret(&secid_uuid))?;
        aw!(delete_policy(&tpid))?;
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

    #[test]
    fn test_get_report_keypair() -> anyhow::Result<()> {
        let tid = "man-moon-dog-face-in-the-banana-patch".to_string();

        let rng = SystemRandom::new();
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();

        aw!(insert_report_keypair(&tid, pkcs8_bytes.as_ref(), None)).unwrap();

        let keypair_vec = aw!(get_report_keypair(&tid)).unwrap();
        assert_eq!(keypair_vec, pkcs8_bytes.as_ref());

        aw!(delete_report_keypair(&tid))?;

        Ok(())
    }

    #[test]
    fn test_get_signing_keys_policy() -> anyhow::Result<()> {
        let testpol = policy::Policy {
            allowed_digests: vec!["0".to_string(), "1".to_string(), "3".to_string()],
            allowed_policies: vec![0u32, 1u32, 2u32],
            min_fw_api_major: 0,
            min_fw_api_minor: 0,
            allowed_build_ids: vec![0u32, 1u32, 2u32],
        };

        let polid = aw!(insert_policy(&testpol))?;

        let mut tid = "man-moon-dog-face-in-the-banana-patch-ksp".to_string();

        let rng = SystemRandom::new();
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();

        // First test with valid policy id
        aw!(insert_report_keypair(
            &tid,
            pkcs8_bytes.as_ref(),
            Option::Some(polid)
        ))
        .unwrap();

        let keypair_policy = aw!(get_signing_keys_policy(&tid))?;
        assert_eq!(keypair_policy, Option::Some(testpol));
        aw!(delete_report_keypair(&tid))?;
        aw!(delete_policy(&polid))?;

        // Now test report_keypair without a policy

        tid = "the-quick-brown-cow-jumped-over-the-moon-no-policy".to_string();

        aw!(insert_report_keypair(&tid, pkcs8_bytes.as_ref(), None))?;

        let keypair_policy = aw!(get_signing_keys_policy(&tid))?;
        assert_eq!(keypair_policy, None);
        aw!(delete_report_keypair(&tid))?;

        Ok(())
    }
}
