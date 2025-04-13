use crate::common::config::*;
use crate::common::helpers::*;
use crate::common::protocol_runner::*;
use crate::function;
use anyhow::{ Context, Result };

#[cfg(test)]
#[ctor::ctor]
fn init() {
    // We need to wait a bit until all nodes connect to NAT's and retrieve their identities
    std::thread::sleep(core::time::Duration::from_millis(500));
}

#[cfg(test)]
#[ctor::dtor]
fn shutdown() {
    // Waiting for node containers to process NAT's messages
    std::thread::sleep(core::time::Duration::from_millis(500));
}

/// cargo run --bin publisher -- -c local -p wa -t ed -n 1,2,3,4,5
/// cargo run --bin publisher -- -c local -p si -t ed -k <key-id> -n 1,2,3
#[tokio::test]
async fn eddsa_sign() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let session_id = new_uuid().to_string();
    let party_nodes = NodeIndices::from_iter([1, 2, 3, 4, 5]);

    let mut protocol_runer = ProtocolRunner::new(config);
    let key_id = session_id.clone();
    let pk = protocol_runer.eddsa_wallet_gen(&nc, &party_nodes, &key_id).await?;
    println!("Generated new public key: {pk} with key id: {key_id}");

    let party_nodes = NodeIndices::from_iter([1, 2, 3]);
    let msg_to_sign = "Sign this please".to_string();
    protocol_runer.eddsa_wallet_sign_and_verify(
        &nc,
        &party_nodes,
        &key_id,
        &session_id,
        msg_to_sign
    ).await?;

    println!("Signature generated successfully for key id: {key_id}");
    Ok(())
}

/// cargo run --bin publisher -- -c local -p si -t ed -k 7a48540c-a1e3-4f22-a9fd-68c01b9d91c -n 1,2,3
#[tokio::test]
async fn eddsa_existing_key_sign() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let mut protocol_runer = ProtocolRunner::new(config);
    let key_id = "7a48540c-a1e3-4f22-a9fd-68c01b9d91cc".to_string();
    let session_id = key_id.clone();
    let party_nodes = NodeIndices::from_iter([1, 2, 3]);
    let msg_to_sign = "Sign this please".to_string();

    protocol_runer.eddsa_wallet_sign_and_verify(
        &nc,
        &party_nodes,
        &key_id,
        &session_id,
        msg_to_sign
    ).await?;

    println!("Signature generated successfully for key id: {key_id}");
    Ok(())
}

/// cargo run --bin publisher -- -c local -p wa -t ed -n 1,2,3,4,5
/// cargo run --bin publisher -- -c local -p re -t ed -k <key-id> -i 3 -n 1,2,5
#[tokio::test]
async fn eddsa_recovery() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let session_id = new_uuid().to_string();
    let party_nodes = NodeIndices::from_iter([1, 2, 3, 4, 5]);

    let mut protocol_runer = ProtocolRunner::new(config);
    let key_id = session_id.clone();
    let pk = protocol_runer.eddsa_wallet_gen(&nc, &party_nodes, &key_id).await?;

    println!("Generated new public key: {pk} with key id: {key_id}");

    let party_nodes = NodeIndices::from_iter([1, 2, 5]);
    let recovery_index = 3;
    let threshold = 2;
    protocol_runer.recovery(
        &nc,
        &key_id,
        &session_id,
        recovery_index,
        threshold,
        party_nodes,
        KeyType::EdDSA
    ).await?;

    println!("Keyfiles regenerated successfully for key id: {key_id}");
    Ok(())
}

/// cargo run --bin publisher -- -c local -p wa -t ec -n 1,2,3,4,5
/// cargo run --bin publisher -- -c local -p si -t ec -k <key-id> -n 1,2,5
#[tokio::test]
async fn ecdsa_sign() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let session_id = new_uuid().to_string();
    let party_nodes = NodeIndices::from_iter([1, 2, 3, 4, 5]);

    let mut protocol_runer = ProtocolRunner::new(config);
    let key_id = session_id.clone();
    protocol_runer.ecdsa_wallet_gen(&nc, &party_nodes, &key_id).await?;
    println!("Generated new public key with key id: {key_id}");

    let party_nodes = NodeIndices::from_iter([1, 2, 5]);
    let msg_to_sign = "Sign this please".to_string();
    protocol_runer.ecdsa_wallet_sign_and_verify(
        &nc,
        &party_nodes,
        &key_id,
        &session_id,
        msg_to_sign
    ).await?;

    println!("Signature generated successfully for key id: {key_id}");
    Ok(())
}

/// cargo run --bin publisher -- -c local -p si -t ec -k b549c9df-c6e1-42b8-a16f-e4f05ab82e14 -n 1,2,5
#[tokio::test]
async fn ecdsa_existing_key_sign() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;

    let mut protocol_runer = ProtocolRunner::new(config);
    let key_id = "b549c9df-c6e1-42b8-a16f-e4f05ab82e14".to_string();
    let session_id = key_id.to_string();
    let party_nodes = NodeIndices::from_iter([1, 2, 3]);
    let msg_to_sign = "Sign this please".to_string();
    protocol_runer.ecdsa_wallet_sign_and_verify(
        &nc,
        &party_nodes,
        &key_id,
        &session_id,
        msg_to_sign
    ).await?;

    println!("Signature generated successfully for key id: {key_id}");
    Ok(())
}

/// cargo run --bin publisher -- -c staging -p wa -t ec -n 1,2,3,4,5
/// cargo run --bin publisher -- -c local -p re -t ec -k <key-id> -i 1 -n 2,3,4
#[tokio::test]
async fn ecdsa_recovery() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let session_id = new_uuid().to_string();
    let party_nodes = NodeIndices::from_iter([1, 2, 3, 4, 5]);

    let mut protocol_runer = ProtocolRunner::new(config);
    let key_id = session_id.clone();
    protocol_runer.ecdsa_wallet_gen(&nc, &party_nodes, &key_id).await?;
    println!("Generated new public key with key id: {key_id}");

    let party_nodes = NodeIndices::from_iter([2, 3, 4]);
    let recovery_index = 1;
    let threshold = 2;
    protocol_runer.recovery(
        &nc,
        &key_id,
        &session_id,
        recovery_index,
        threshold,
        party_nodes,
        KeyType::ECDSA
    ).await?;

    println!("Keyfiles regenerated successfully for key id: {key_id}");
    Ok(())
}

/// cargo run --bin publisher -- -c local -p 2fa -f 12345678 -n 1,2,3,4,5 -o 1
/// cargo run --bin publisher -- -c local -p re -t twofa -k a8bef03b-0657-4a36-959d-6609b0dd16d7 -i 1 -n 2,3,5
#[tokio::test]
async fn twofa_recovery() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let session_id = new_uuid().to_string();
    let party_nodes = NodeIndices::from_iter([1, 2, 3, 4, 5]);
    let threshold = 2;
    let share_count = 5;
    let owner_node = 1;
    let key_id = session_id.clone();

    let mut protocol_runer = ProtocolRunner::new(config);
    protocol_runer.twofa_import(
        &nc,
        &key_id,
        "12345678",
        threshold,
        share_count,
        &party_nodes,
        owner_node
    ).await?;
    println!("Generated new public key with key id: {key_id}");

    let recovery_index = 1;

    delete_file(FileKind::Key, recovery_index, &key_id)?;

    let party_nodes = NodeIndices::from_iter([2, 3, 5]);
    protocol_runer.recovery(
        &nc,
        &key_id,
        &session_id,
        recovery_index,
        threshold,
        party_nodes,
        KeyType::TwoFA
    ).await?;

    println!("Keyfiles regenerated successfully for key id: {key_id}");
    Ok(())
}

/// cargo run --bin publisher -- -c local -p wa -t sr -o 1 -n 1,2,3,4,5
/// cargo run --bin publisher -- -c local -p re -t twofa -k 051f8d85-4558-469f-82a1-4f3e53beef22 -i 1 -n 2,3,5
/// cargo run --bin publisher -- -c local -p si -t sr -k 051f8d85-4558-469f-82a1-4f3e53beef22 -o 1
#[tokio::test]
async fn sr25519_sign_recovery() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let session_id = new_uuid().to_string();
    let party_nodes = NodeIndices::from_iter([1, 2, 3, 4, 5]);
    let threshold = 2;
    let share_count = 5;
    let owner_node = 1;
    let key_id = session_id.clone();

    let mut protocol_runer = ProtocolRunner::new(config);
    protocol_runer.sr25519_wallet_gen(
        &nc,
        &key_id,
        threshold,
        share_count,
        &party_nodes,
        owner_node
    ).await?;
    println!("Generated new public key with key id: {key_id}");

    let recovery_index = 1;

    delete_file(FileKind::Key, recovery_index, &key_id)?;

    let party_nodes = NodeIndices::from_iter([2, 3, 5]);
    protocol_runer.recovery(
        &nc,
        &key_id,
        &session_id,
        recovery_index,
        threshold,
        party_nodes,
        KeyType::Sr25519
    ).await?;

    println!("Keyfiles regenerated successfully for key id: {key_id}");

    protocol_runer.sr25519_wallet_sign_and_verify(
        &nc,
        &key_id,
        owner_node,
        "Sign me please!".to_string()
    ).await?;
    Ok(())
}
