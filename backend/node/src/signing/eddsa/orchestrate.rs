use crate::command::MsgContext;
use crate::communication::nats::{ BroadcastMessage, JoinMessage, JoinResponse };
use crate::signing::eddsa::session::NewEdDSAKeySignSession;
use crate::signing::eddsa::SignatureResult;
use crate::signing::{ SigningCommand, SigningResponse };
use anyhow::{ bail, Context, Result };
use tracing::{ error, info, instrument };

#[instrument(skip_all)]
pub fn orchestrate(cmd: SigningCommand, ctx: MsgContext) -> Result<SigningResponse> {
    let app = ctx.get_app()?;
    let nc = app.nc;
    let session_id = cmd.session_id.clone();

    let party_nodes = cmd.party_nodes;
    let key_id = cmd.key_id;

    let party_count = party_nodes.len();
    if party_count < 3 {
        bail!("Not enough nodes in party");
    }

    let join_key = format!("network.gridlock.nodes.EphemeralKeyGenEdDSA.{}.Join", &session_id);
    let join_sub = nc.subscribe(&join_key)?;

    let result_key = format!("network.gridlock.nodes.KeySignEdDSA.{}.Result", &session_id);
    let result_sub = nc.subscribe(&result_key)?;

    for node in party_nodes.iter() {
        let sign_new_key = format!("network.gridlock.nodes.KeySignEdDSA.new.{}", node);
        let key_sign_new_data = serde_json::to_string(
            &(NewEdDSAKeySignSession {
                key_id: key_id.to_owned(),
                session_id: session_id.to_owned(),
                message: cmd.msg.clone(),
                email: None,
            })
        )?;
        nc.publish(&sign_new_key, key_sign_new_data)?;
    }

    let mut join_msg_vec = Vec::new();
    for _i in 0..party_count {
        let next = join_sub.next().unwrap();
        join_msg_vec.push(next);
    }

    if join_msg_vec.len() < party_count {
        let msg = format!("Not every party joined - party_joined_count: {}", join_msg_vec.len());
        error!("{}", &msg);
        bail!(msg);
    }

    let mut indices = Vec::new();
    for m in join_msg_vec.iter() {
        let confirmation = serde_json::from_slice::<JoinMessage>(&m.data)?;
        indices.push(confirmation.party_index);
    }
    indices.sort();
    let join_resp = JoinResponse {
        party_count: indices.len(),
        all_party_indices: indices,
    };
    for msg in join_msg_vec {
        msg.respond(
            &serde_json::to_string(&join_resp).context("Respond to join message for every party")?
        )?;
    }
    nc.flush()?;

    info!("Parties joined to ecdsa signing");

    let mut res_vec = Vec::new();
    for _ in 0..party_count {
        let res = result_sub.next().unwrap();
        res_vec.push(res);
    }

    info!("Signature result received");

    let sig = serde_json::from_slice::<BroadcastMessage<SignatureResult>>(
        &res_vec[0].data
    )?.message;
    Ok(SigningResponse::EDDSA(sig))
}
