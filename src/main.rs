// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use clap::{Command, Arg};
use log::*;
use std::net::SocketAddr;

pub mod db;
pub mod grpc;
pub mod policy;
pub mod request;
pub mod sev_tools;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Command::new("kbs-rs")
        .version("0.0.1")
        .arg(
            Arg::new("socket addr")
                .long("grpc_sock")
                .takes_value(true)
                .help("Socket that the server will listen on."),
        )
        .get_matches();

    let socket = args
        .value_of("socket addr")
        .unwrap_or("127.0.0.1:44444")
        .parse::<SocketAddr>()?;

    info!("Starting gRPC Server");
    grpc::start_service(socket).await?;

    Ok(())
}
