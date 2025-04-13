use derive_more::Display;
use std::str::FromStr;

#[derive(Debug)]
pub struct Network {
    pub address: String,
    pub ntype: NetworkType,
}

#[derive(Debug, Display)]
pub enum NetworkType {
    Local,
    Staging,
    Production,
}

impl FromStr for Network {
    type Err = ParseNetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let network = match s {
            "local" =>
                Self {
                    ntype: NetworkType::Local,
                    address: "nats://localhost:4222".to_string(),
                },
            "staging" =>
                Self {
                    ntype: NetworkType::Staging,
                    address: "nats://stagingnats.gridlock.network:4222".to_string(),
                },
            "prod" =>
                Self {
                    ntype: NetworkType::Production,
                    address: "nats://app.gridlock.network:4222".to_string(),
                },
            _ => {
                return Err(Self::Err::InvalidString {
                    found: s.to_string(),
                });
            }
        };

        Ok(network)
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseNetworkError {
    #[error(
        "Invalid network (expected `local`, `staging` or `prod`, got {found:?})"
    )] InvalidString {
        found: String,
    },
}
