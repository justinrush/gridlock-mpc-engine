use crate::command::{ JsonCommand, MsgContext };
use crate::storage::fs::WriteOpts;
use crate::storage::KeyInfoStore;
use anyhow::Result;
use shared::key_info::UpdateKeyInfoCommand;

impl JsonCommand for UpdateKeyInfoCommand {
    type Response = ();

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        KeyInfoStore::save_key_info(&self.key_info, &self.key_id, &WriteOpts::Modify)
    }
}
