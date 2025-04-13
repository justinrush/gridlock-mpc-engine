// use crate::common::network::{Network, NetworkType};
// use crate::test::common::network::{Network, NetworkType};
mod common;

use crate::common::network::*;
use anyhow::{ anyhow, bail, Result };
use chrono::offset::Local;
use std::thread;
use std::time::Duration;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
struct Opt {
    #[structopt(short = "c", long = "network")]
    network: Network,
}

#[cfg(not(test))]
fn main() -> Result<()> {
    let network: Network = Opt::from_args().network;
    let nc = loop {
        match
            nats::Options
                ::with_user_pass(
                    "node",
                    "68da8b26e61039cff90bb9ca5bc78a239b049bb9c4e5cc79147364f3653f8f"
                )
                .connect(&network.address)
        {
            Ok(nc) => {
                break nc;
            }
            Err(err) =>
                match network.ntype {
                    NetworkType::Local => thread::sleep(Duration::from_millis(50)),
                    _ => bail!(err),
                }
        }
    };

    let sub = nc.subscribe(">")?;
    println!("Listening to nats {} network, time is {}", network.ntype, Local::now());
    loop {
        match sub.next() {
            Some(msg) => println!("{:?}:{}:{}", Local::now(), network.ntype, msg),
            None => {
                println!("Connection ended");
                break;
            }
        };
    }
    Ok(())
}
