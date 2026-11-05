//! Identity sources and the STS token exchange for Prego by Katskill clients.
//!
//! A client finds a subject token on the machine ([`sources`]), sends it to the Prego STS ([`sts`]) and
//! gets a short-lived registry token. [`TokenClient`] does both steps and keeps the result in memory.
//!
//! This crate never prints, logs or writes a token to disk. Token values are held in [`Secret`].

#![forbid(unsafe_code)]

mod client;
pub mod config;
pub mod env;
mod error;
pub mod file_config;
pub mod go;
pub mod http;
pub mod jwt;
pub mod npm;
pub mod oci;
mod secret;
pub mod sources;
pub mod sts;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing;

pub use client::TokenClient;
pub use config::{Config, SourceChoice, DEFAULT_AUDIENCE, DEFAULT_STS_URL};
pub use env::{Env, MapEnv, ProcessEnv};
pub use error::Error;
pub use file_config::FileConfig;
pub use secret::Secret;
pub use sources::{SourceKind, SubjectToken, TokenType};
pub use sts::RegistryToken;

/// Returns the current Unix time in seconds.
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
