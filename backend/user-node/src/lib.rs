#![allow(dead_code)]
#![allow(non_snake_case)]

use anyhow::{ anyhow, bail, Result };
use node::node::NodeIdentity;
use node::start_sending_ready_as_cancellable_task_on_thread;
use node::{ create_new_node_identity, get_nats_connection, handle_message, App };
use std::sync::{ mpsc, mpsc::TryRecvError };
use std::time::Duration;
use tracing::info;

#[cfg(any(target_os = "android", target_os = "ios"))]
mod build_info;
#[cfg(any(target_os = "android", target_os = "ios"))]
mod os;

const READY_MSG_INTERVAL: Duration = Duration::from_millis(200);

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn connect_and_listen(_: &str) -> Result<()> {
    let app = App::new()?;

    let wildcard_subject = format!("network.gridlock.nodes.*.new.{}", &app.node.node_id);

    let wildcard_subscription = app.nc
        .subscribe(&wildcard_subject)
        .map_err(|_| anyhow!("Failed to subscribe to subject \"{}\"", wildcard_subject))?;
    info!("Subscribed to NATS subject \"{}\"", wildcard_subject);

    //Send periodic ready messages until we receive message or time out

    //Send ready message and listen on nats until timeout
    let connection = app.nc.clone();
    let node_id = app.node.node_id.to_string();
    let subject = format!("network.gridlock.nodes.ready.{}", &node_id);
    let (tx, rx) = mpsc::channel();

    let _ = start_sending_ready_as_cancellable_task_on_thread(
        connection,
        node_id,
        rx,
        READY_MSG_INTERVAL
    );

    let mut msg_count = 0;
    for msg in wildcard_subscription.timeout_iter(std::time::Duration::from_secs(15)) {
        msg_count += 1;
        info!("Recieved {} message(s) so far while waiting", msg_count);
        handle_message(&app, msg);
    }
    let _ = tx.send(());

    info!("Stopped listening for messages, recieved {}", msg_count);

    if msg_count == 0 {
        bail!("Timeout while waiting for a message from the server");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use node::start_sending_ready_as_cancellable_task_on_thread;
    #[test]
    #[ignore]
    fn ready_loop_is_cancellable() {
        let (tx, rx) = mpsc::channel();

        let _ = start_sending_ready_as_cancellable_task_on_thread(
            nats::connect(&"nats://staging.gridlock.network:4222".to_string()).unwrap(),
            "NODEID".to_string(),
            rx,
            Duration::from_millis(500)
        );

        println!("Waiting..");
        std::thread::sleep(Duration::from_secs(4));
        println!("Stopping..");
        let _ = tx.send(()).unwrap();
        println!("Stopped?");
    }
}
