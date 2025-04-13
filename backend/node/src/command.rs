use crate::eject::{ EjectKeysCommand, EjectSharesCommand };
use crate::keygen::key_import::{
    KeyImportCommand,
    KeyImportShareCommand,
    TwoFACodeRetrievalCommand,
};
use crate::keygen::sr25519::KeyGenCommand as Sr25519KeyGenCommand;
use crate::keygen::KeyGenCommand;
use crate::recovery::{ GetPaillierKeysCommand, RecoveryCommand };
use crate::signing::sr25519::KeySignCommand as Sr25519KeySignCommand;
use crate::signing::SigningCommand;
use crate::storage::keyshare_index_info::{ get_all_keyshare_indices, KeyshareIndex };
use crate::App;
use anyhow::{ anyhow, bail, Result };
use serde::{ Deserialize, Serialize };
use shared::key_info::UpdateKeyInfoCommand;
use shared::recovery::{
    ReceiveRecoveryPackages,
    UpdatePaillierKeysCommand,
    UpdateSinglePaillierKeyCommand,
};
use std::fmt::Debug;
use std::thread;
use tracing::{ error, info };

pub enum MsgContext {
    NATS(App),
    FFI,
}

impl MsgContext {
    pub fn get_app(&self) -> Result<App> {
        match self {
            MsgContext::NATS(app) => Ok(app.clone()),
            MsgContext::FFI => App::new(),
        }
    }

    fn get_encoder(&self) -> Encoder {
        match self {
            MsgContext::NATS(_) => Encoder::PlaintextEncoder,
            MsgContext::FFI => Encoder::B64Encoder,
        }
    }
}

pub fn handle_nats_command(app: &App, message: nats::Message) -> Result<()> {
    let request = String::from_utf8(message.data.clone())?;
    let app = app.clone();
    let subject = message.subject.clone();

    match
        thread::Builder
            ::new()
            .name(subject.clone())
            .spawn(move || {
                let response = handle_json_message(&request, MsgContext::NATS(app)).unwrap_or_else(
                    |err| format!("ERROR: {}", err)
                );

                if message.reply.is_some() {
                    match message.respond(response) {
                        Ok(_) => {}
                        Err(err) => error!("Unable to respond to nats message: {}", err),
                    }
                }
            })
    {
        Ok(_) => Ok(()),
        Err(_) => bail!("Failed to spawn thread for keygen session for subject {}", subject),
    }
}

pub fn handle_json_message(request: &str, source: MsgContext) -> Result<String> {
    process_request(request, source).map_err(|err| {
        let msg = format!("Could not process received message: {}, message was {}", err, request);
        error!("{}", &msg);
        anyhow!("{}", &msg)
    })
}

fn process_request<T>(request: T, ctx: MsgContext) -> Result<String> where T: AsRef<[u8]> {
    let encoder = ctx.get_encoder();
    let command = encoder.decode(request).map_err(|_| anyhow!("Could not decode message"))?;
    let response = match serde_json::from_slice::<TaggedCommandType>(&command) {
        Ok(tagged_cmd) =>
            (match tagged_cmd {
                TaggedCommandType::OrchestrateKeyGen(cmd) => cmd.execute(ctx),
                TaggedCommandType::OrchestrateSigning(cmd) => cmd.execute(ctx),
                TaggedCommandType::OrchestrateRecovery(cmd) => cmd.execute(ctx),
            })?,
        Err(e) =>
            (match serde_json::from_slice::<CommandType>(&command)? {
                CommandType::KeyImport(cmd) => cmd.execute(ctx),
                CommandType::KeyImportShare(cmd) => cmd.execute(ctx),
                CommandType::KeyshareRecovery(cmd) => cmd.execute(ctx),
                CommandType::UpdatePaillierKeys(cmd) => cmd.execute(ctx),
                CommandType::UpdateSinglePaillierKey(cmd) => cmd.execute(ctx),
                CommandType::Parameterless(cmd) => cmd.execute(ctx),
                CommandType::TwoFACodeRetrieval(cmd) => cmd.execute(ctx),
                CommandType::EjectShares(cmd) => cmd.execute(ctx),
                CommandType::EjectKeys(cmd) => cmd.execute(ctx),
                CommandType::Sr25519KeyGen(cmd) => cmd.execute(ctx),
                CommandType::Sr25519KeySign(cmd) => cmd.execute(ctx),
                CommandType::UpdateKeyInfo(cmd) => cmd.execute(ctx),
                CommandType::GetPaillierKeys(cmd) => cmd.execute(ctx),
            })?,
    };

    encoder.encode(&response)
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommandType {
    KeyImport(KeyImportCommand),
    KeyImportShare(KeyImportShareCommand),
    Sr25519KeyGen(Sr25519KeyGenCommand),
    Sr25519KeySign(Sr25519KeySignCommand),
    KeyshareRecovery(ReceiveRecoveryPackages),
    UpdatePaillierKeys(UpdatePaillierKeysCommand),
    UpdateSinglePaillierKey(UpdateSinglePaillierKeyCommand),
    Parameterless(ParameterlessCommand),
    TwoFACodeRetrieval(TwoFACodeRetrievalCommand),
    EjectShares(EjectSharesCommand),
    EjectKeys(EjectKeysCommand),
    UpdateKeyInfo(UpdateKeyInfoCommand),
    GetPaillierKeys(GetPaillierKeysCommand),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "cmd")]
pub enum TaggedCommandType {
    OrchestrateKeyGen(KeyGenCommand),
    OrchestrateSigning(SigningCommand),
    OrchestrateRecovery(RecoveryCommand),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub enum ParameterlessCommand {
    KeyshareInfo,
}

impl JsonCommand for ParameterlessCommand {
    type Response = Vec<KeyshareIndex>;
    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        match self {
            ParameterlessCommand::KeyshareInfo => get_all_keyshare_indices(),
        }
    }
}

pub trait JsonCommand: Debug {
    type Response: Serialize;
    fn execute(self, ctx: MsgContext) -> Result<String> where Self: Sized {
        self.log_message();
        let response = self.execute_message(ctx)?;
        info!("Message processed successfully");
        let res = serde_json::to_string(&response)?;
        Ok(res)
    }

    fn log_message(&self) {
        info!("Received message: {:?}", &self)
    }

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized;
}

enum Encoder {
    B64Encoder,
    PlaintextEncoder,
}

impl Encoder {
    fn decode<T>(&self, encoded: T) -> Result<Vec<u8>> where T: AsRef<[u8]> {
        match self {
            Encoder::B64Encoder => base64::decode(encoded).map_err(|err| anyhow!("{}", err)),
            Encoder::PlaintextEncoder => Ok(encoded.as_ref().to_vec()),
        }
    }

    fn encode<T>(&self, msg: T) -> Result<String> where T: AsRef<[u8]> {
        match self {
            Encoder::B64Encoder => Ok(base64::encode(msg)),
            Encoder::PlaintextEncoder => {
                String::from_utf8(msg.as_ref().to_vec()).map_err(|err| anyhow!("{}", err))
            }
        }
    }
}
