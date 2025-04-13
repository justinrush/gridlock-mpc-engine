use std::fmt::Display;
use std::iter::Iterator;
use strum::IntoEnumIterator;
use strum_macros::{ Display as macroDisplay, EnumIter };

pub trait AllRounds {
    type BroadcastRound: Display + IntoEnumIterator;
    type P2PRound: Display + IntoEnumIterator;
}

#[derive(macroDisplay)]
pub enum Topic {
    KeyGenEdDSA,
    EphemeralKeyGenEdDSA,
    KeySignEdDSA,
    KeyShareRecovery,
    KeySignSr25519,
}

pub struct KeyGenAllRounds;

impl AllRounds for KeyGenAllRounds {
    type BroadcastRound = KeyGenBroadcastRound;
    type P2PRound = KeyGenP2PRound;
}

#[derive(macroDisplay, EnumIter)]
pub enum KeyGenBroadcastRound {
    Commit,
    Decommit,
    VSS,
    Result,
}

#[derive(macroDisplay, EnumIter)]
pub enum KeyGenP2PRound {
    ShareSecret,
}

pub struct KeySignEdDSAAllRounds;

impl AllRounds for KeySignEdDSAAllRounds {
    type BroadcastRound = KeySignBroadcastRound;
    type P2PRound = KeySignP2PRound;
}

#[derive(macroDisplay, EnumIter)]
pub enum KeySignBroadcastRound {
    LocalSig,
    Result,
}

#[derive(macroDisplay, EnumIter)]
pub enum KeySignP2PRound {}

pub struct KeyShareRegenAllRounds;

impl AllRounds for KeyShareRegenAllRounds {
    type BroadcastRound = KeyShareRegenBroadcastRound;
    type P2PRound = KeyShareRegenP2PRound;
}

#[derive(macroDisplay, EnumIter)]
pub enum KeyShareRegenBroadcastRound {
    DeliverRecoveryPackage,
    ValidationResult,
}

#[derive(macroDisplay, EnumIter)]
pub enum KeyShareRegenP2PRound {
    ExchangePartShares,
}

#[derive(macroDisplay, EnumIter)]
pub enum SrMusig25519BroadcastRound {
    Reveal,
    Commit,
    Cosign,
    Result,
}

pub struct KeySignSr25519AllRounds;

impl AllRounds for KeySignSr25519AllRounds {
    type BroadcastRound = SrMusig25519BroadcastRound;
    type P2PRound = KeySignP2PRound;
}
