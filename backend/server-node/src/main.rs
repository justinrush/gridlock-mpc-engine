use anyhow::{ anyhow, bail, Result };
use nats::Subscription;
use node::{
    handle_message,
    start,
    start_sending_ready_as_cancellable_task_on_thread,
    App,
    NATS_CONNECTED,
};
use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::mpsc::TryRecvError;
use std::sync::{ mpsc, Arc };
use std::time::Duration;
use tracing::{ error, warn };

const READY_MSG_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    let app = match start() {
        Ok(setup) => setup,
        Err(err) => {
            let msg = format!("Node start was unsuccessful: {err:?}");
            error!("{msg:?}");
            panic!("{msg:?}");
        }
    };

    let (tx, rx) = mpsc::channel();
    let _ = start_sending_ready_as_cancellable_task_on_thread(
        app.nc.clone(),
        app.node.node_id.to_string(),
        rx,
        READY_MSG_INTERVAL
    );

    match message_loop(app) {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
        }
    }

    let _ = tx.send(());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn message_loop(mut app: App) -> Result<()> {
    let mut subscription = subscribe(&app)?;

    let has_terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag
        ::register(signal_hook::SIGTERM, Arc::clone(&has_terminate))
        .expect("SIGTERM Signal hook registered");

    while !has_terminate.load(Ordering::Relaxed) {
        // Timeout is necessary to check whether SIGTERM called
        match subscription.next_timeout(Duration::from_millis(1000)) {
            Ok(msg) => {
                handle_message(&app, msg);
            }
            Err(e) => {
                if !NATS_CONNECTED.load(Ordering::Relaxed) {
                    match app.try_reconnect() {
                        Ok(_) => {
                            subscription = subscribe(&app)?;
                        }
                        Err(e) => {
                            warn!("Couldn't reconnect to NATs - {}", e);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn subscribe(app: &App) -> Result<Subscription> {
    let subject = format!("network.gridlock.nodes.*.new.{}", &app.node.node_id);
    match app.nc.subscribe(&subject) {
        Ok(sub) => Ok(sub),
        Err(err) => { bail!("Failed to subscribe to subject \"{}\" :{}", subject, err) }
    }
}
