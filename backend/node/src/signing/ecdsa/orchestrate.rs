use crate::command::MsgContext;
use crate::signing::ecdsa::{ JoinSignSessionResponse, NewSignSession, SigningResult };
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
        let msg = "Not enough nodes in party";
        error!("{}", msg);
        bail!(msg);
    }

    let join_key = format!("network.gridlock.nodes.keySign.session.{session_id}.join");
    let join_sub = nc.subscribe(&join_key)?;

    let result_key = format!("network.gridlock.nodes.keySign.session.{}.result", &session_id);
    let result_sub = nc.subscribe(&result_key)?;

    let new_sign_session_msg = serde_json::to_string(
        &(NewSignSession {
            session_id: session_id.clone(),
            key_id,
            message: cmd.msg.clone(),
        })
    )?;
    for node_id in party_nodes.iter() {
        let key_sign_key = format!("network.gridlock.nodes.keySign.new.{node_id}");
        nc.publish(&key_sign_key, &new_sign_session_msg)?;
    }

    for i in 0..party_count {
        let next = join_sub.next().context("Get next join message")?;

        next
            .respond(
                &serde_json::to_string(
                    &(JoinSignSessionResponse {
                        id_in_session: i,
                        message: cmd.msg.clone(),
                    })
                )?
            )
            .context("Respond to join message for every party")?;

        nc.flush().context("Flush nats connection")?;
    }

    info!("Parties joined to ecdsa signing");

    nc.publish(
        &format!("network.gridlock.nodes.keySign.session.{session_id}.start"),
        &serde_json::to_string(&party_count).unwrap()
    )?;

    let mut res_vec = Vec::new();

    for _ in 0..party_count {
        let res = result_sub.next().context("Signature result received from every party")?;
        res_vec.push(res);
    }

    info!("Signature result received");

    let sig = serde_json::from_slice::<SigningResult>(&res_vec[0].data)?;
    Ok(SigningResponse::ECDSA(sig))
}
