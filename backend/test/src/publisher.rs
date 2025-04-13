mod common;

use anyhow::{ bail, Result };
use common::config::*;
use common::protocol_runner::*;
use log::info;
use std::num::ParseIntError;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "basic")]
struct Opt {
    #[structopt(short = "c", long = "network")]
    network: Config,
    #[structopt(name = "protocol", short = "p", long = "protocol")]
    protocol: Protocol,
    #[structopt(
        short = "t",
        long = "keytype",
        required_if("protocol", "re"),
        required_if("protocol", "si"),
        required_if("protocol", "wa")
    )]
    key_type: Option<KeyType>,
    #[structopt(name = "nodes", short = "n")]
    party_nodes: Option<NodeIndices>,
    #[structopt(name = "index", short = "i", required_if("protocol", "re"))]
    recovery_index: Option<usize>,
    #[structopt(
        name = "key_id",
        short = "k",
        required_if("protocol", "si"),
        required_if("protocol", "re")
    )]
    key_id: Option<String>,
    #[structopt(name = "key_ids", required_if("key_type", "msr"))]
    party_key_ids: Option<PartyKeys>,
    #[structopt(name = "fa", short = "f", required_if("protocol", "2fa"))]
    two_factor_code: Option<String>,
    #[structopt(
        name = "owner",
        short = "o",
        required_if("protocol", "2fa"),
        required_if("key_type", "sr")
    )]
    owner: Option<usize>,
    #[structopt(name = "message", short = "m", long = "msg")]
    msg: Option<String>,
}

impl FromStr for Protocol {
    type Err = ParseProtocolError;

    fn from_str(input: &str) -> Result<Protocol, Self::Err> {
        match input {
            "wa" => Ok(Protocol::WalletGen),
            "si" => Ok(Protocol::Signature),
            "re" => Ok(Protocol::Recovery),
            "2fa" => Ok(Protocol::TwoFAImport),
            "cust" => Ok(Protocol::Custom),
            _ =>
                Err(ParseProtocolError::InvalidString {
                    found: input.to_string(),
                }),
        }
    }
}

impl FromStr for KeyType {
    type Err = ParseKeyTypeError;

    fn from_str(input: &str) -> Result<KeyType, Self::Err> {
        match input {
            "ed" => Ok(KeyType::EdDSA),
            "ec" => Ok(KeyType::ECDSA),
            "twofa" => Ok(KeyType::TwoFA),
            "sr" => Ok(KeyType::Sr25519),
            "msr" => Ok(KeyType::MultiSr25519),
            _ =>
                Err(ParseKeyTypeError::InvalidString {
                    found: input.to_string(),
                }),
        }
    }
}

impl FromStr for Config {
    type Err = ParseConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config = match s {
            "local" => Self::new_local()?,
            "staging" => Self::new_staging()?,
            "prod" => unimplemented!(),
            _ => {
                return Err(Self::Err::InvalidString {
                    found: s.to_string(),
                });
            }
        };

        Ok(config)
    }
}

impl FromStr for NodeIndices {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hs: Vec<&str> = s.split(',').collect();

        let hs = hs
            .iter()
            .map(|x| x.parse::<usize>())
            .collect::<Result<_, _>>()?;

        Ok(NodeIndices::new(hs))
    }
}

impl FromStr for PartyKeys {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PartyKeys::new(s.split(',').map(str::to_string).collect()))
    }
}

#[derive(Debug, PartialEq)]
pub enum Protocol {
    WalletGen,
    Signature,
    Recovery,
    TwoFAImport,
    Custom,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config: Config = Opt::from_args().network;
    let protocol: Protocol = Opt::from_args().protocol;
    let nc = nats::asynk::Options
        ::with_user_pass(
            // "node",
            // "68da8b26e61039cff90bb9ca5bc78a239b049bb9c4e5cc79147364f3653f8f",
            "admin",
            "2711b50ccffcd2d0db7319f7fca22f8cc5b0a238110ee59b7b763fa0f46d53"
        )
        .connect(&config.address).await?;

    let session_id = new_uuid().to_string();
    let party_nodes = Opt::from_args().party_nodes.unwrap_or_default();
    let key_type = Opt::from_args().key_type;

    let mut protocol_runner = ProtocolRunner::new(config);

    match (protocol, key_type) {
        (Protocol::WalletGen, Some(KeyType::EdDSA)) => {
            let key_id = session_id;
            println!("key id: {key_id}");
            let pk = protocol_runner.eddsa_wallet_gen(&nc, &party_nodes, &key_id).await?;
            println!("Generated new public key: {pk} with key id: {key_id}");
        }
        (Protocol::WalletGen, Some(KeyType::ECDSA)) => {
            let key_id = session_id;
            println!("key id: {key_id}");

            protocol_runner.ecdsa_wallet_gen(&nc, &party_nodes, &key_id).await?;
            println!("Generated new key - key id: {key_id}");
        }
        (Protocol::WalletGen, Some(KeyType::Sr25519)) => {
            let key_id = session_id;
            println!("key id: {key_id}");
            let threshold = 2;
            let share_count = 5;
            let owner = Opt::from_args().owner.unwrap();

            protocol_runner.sr25519_wallet_gen(
                &nc,
                &key_id,
                threshold,
                share_count,
                &party_nodes,
                owner
            ).await?;
            println!("Generated new key - key id: {key_id}");
        }
        (Protocol::Signature, Some(KeyType::EdDSA)) => {
            let key_id: String = Opt::from_args().key_id.unwrap();
            println!("key id: {key_id}");
            let msg: String = Opt::from_args().msg.unwrap_or_else(||
                "Sign this please".to_string()
            );
            println!("Message to sign is: '{msg}'");

            protocol_runner.eddsa_wallet_sign_and_verify(
                &nc,
                &party_nodes,
                &key_id,
                &session_id,
                msg
            ).await?;
            println!("Signature generated successfully");
        }
        (Protocol::Signature, Some(KeyType::ECDSA)) => {
            let key_id: String = Opt::from_args().key_id.unwrap();
            println!("key id: {key_id}");
            let msg: String = Opt::from_args().msg.unwrap_or_else(||
                "Sign this please".to_string()
            );
            println!("Message to sign is: '{msg}'");

            protocol_runner.ecdsa_wallet_sign_and_verify(
                &nc,
                &party_nodes,
                &key_id,
                &session_id,
                msg
            ).await?;
        }
        (Protocol::Signature, Some(KeyType::Sr25519)) => {
            let key_id: String = Opt::from_args().key_id.unwrap();
            println!("key id: {key_id}");
            let msg: String = Opt::from_args().msg.unwrap_or_else(||
                "Sign this please".to_string()
            );
            println!("Message to sign is: '{msg}'");

            let owner = Opt::from_args().owner.unwrap();

            protocol_runner.sr25519_wallet_sign_and_verify(&nc, &key_id, owner, msg).await?;
        }
        (Protocol::Signature, Some(KeyType::MultiSr25519)) => {
            let key_id: String = Opt::from_args().key_id.unwrap();
            let party_key_ids: PartyKeys = Opt::from_args().party_key_ids.unwrap();
            println!("key id: {key_id}");
            let msg: String = Opt::from_args().msg.unwrap_or_else(||
                "Sign this please".to_string()
            );
            println!("Message to sign is: '{msg}'");
            let owner = Opt::from_args().owner.unwrap();

            protocol_runner.sr25519_wallet_multi_sign_and_verify(
                &nc,
                &key_id,
                party_key_ids,
                &party_nodes,
                owner,
                msg
            ).await?;
        }
        (Protocol::Recovery, Some(key_type)) => {
            let recovery_index: usize = Opt::from_args().recovery_index.unwrap();
            let key_id: String = Opt::from_args().key_id.unwrap();
            let threshold = 2;

            protocol_runner.recovery(
                &nc,
                &key_id,
                &session_id,
                recovery_index,
                threshold,
                party_nodes,
                key_type
            ).await?;
        }
        (Protocol::TwoFAImport, _) => {
            let threshold = 2;
            let share_count = 5;
            let key_id = session_id;
            let two_factor_code: String = Opt::from_args().two_factor_code.unwrap();
            let owner = Opt::from_args().owner.unwrap();
            protocol_runner.twofa_import(
                &nc,
                &key_id,
                &two_factor_code,
                threshold,
                share_count,
                &party_nodes,
                owner
            ).await?;
        }
        (Protocol::Custom, _) => {
            let msg = Opt::from_args().msg.expect("Message to send via nats");
            let node_index = Opt::from_args().owner.expect("Node to perform cmd");
            protocol_runner.customisable(&nc, node_index, msg).await?;
        }
        _ => {
            info!("Invalid input");
            bail!("Invalid input");
        }
    }

    Ok(())
}
