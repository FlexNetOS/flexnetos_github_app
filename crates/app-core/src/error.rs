//! Aggregate error type for `app-core`. Each module owns its own error; `CoreError`
//! is the unifying boundary type for front-ends that drive several seams.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Signature(#[from] crate::webhook::SignatureError),
    #[error(transparent)]
    Jwt(#[from] crate::jwt::JwtError),
    #[error(transparent)]
    Mint(#[from] crate::mint::MintError),
    #[error(transparent)]
    MergeGate(#[from] crate::merge_gate::MergeGateError),
}

pub type Result<T> = std::result::Result<T, CoreError>;
