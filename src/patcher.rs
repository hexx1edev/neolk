//! Binary patch engine

use crate::{device::Patch, image::LkImage};
use std::fmt;

#[derive(Debug)]
pub enum PatchError {
    NoPartition(String),
    InvalidReplacement,
    InvalidHex(String),
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::NoPartition(part) => write!(f, "partition not found: {part}"),
            PatchError::InvalidReplacement => write!(f, "invalid replacement"),
            PatchError::InvalidHex(hex) => write!(f, "invalid replacement: {hex}"),
        }
    }
}

impl std::error::Error for PatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub struct Patcher {}

impl Patcher {
    pub fn apply(image: &mut LkImage, patch: &Patch) -> Result<(), PatchError> {
        if !image.partitions.contains_key(&patch.target) {
            return Err(PatchError::NoPartition(patch.target.clone()));
        }

        let pattern = Self::parse_hex_bytes(patch.pattern.as_str())?;
        let replacement = Self::parse_hex_bytes(patch.replacement.as_str())?;

        if pattern.is_empty() || pattern.len() != replacement.len() {
            return Err(PatchError::InvalidReplacement);
        }

        let target = image
            .partitions
            .get_mut(&patch.target)
            .ok_or(PatchError::NoPartition(patch.target.clone()))?;

        if let Some(offset) = target
            .data
            .windows(pattern.len())
            .position(|bytes| bytes == pattern.as_slice())
        {
            target.data[offset..offset + replacement.len()].copy_from_slice(&replacement);
        }

        Ok(())
    }

    fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, PatchError> {
        text.split_ascii_whitespace()
            .map(|token| {
                if token.len() != 2 {
                    return Err(PatchError::InvalidHex(token.to_owned()));
                }

                u8::from_str_radix(token, 16).map_err(|_| PatchError::InvalidHex(token.to_owned()))
            })
            .collect()
    }
}
