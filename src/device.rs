//! Device TOML configuration, patches, payloads parsing

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Device {
    pub name: String,
    pub binary: String,
    pub cert: Cert
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Cert {
    Skip,
    Override
}

impl Device {
    pub fn new(text: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let device: Device = toml::from_str(text)?;

        Ok(device)
    }
}

#[derive(Debug)]
pub struct Patch {
    pub name: String,
    pub pattern: String,
    pub replacement: String,
    pub target: String
}

#[derive(Debug)]
pub struct Patches {
    pub vec: Vec<Patch>
}

impl Patches {
    pub fn new(text: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let document: toml::Value = toml::from_str(text)?;

        if let Some(patches) = document.as_table() {
            let mut vec: Vec<Patch> = Vec::new();

            for (patch_name, value) in patches {
                let patch = value.as_table().ok_or("Invalid patch")?;

                let pattern = patch.get("pattern").and_then(toml::Value::as_str);
                let replacement = patch.get("replacement").and_then(toml::Value::as_str);
                let target = patch.get("target").and_then(toml::Value::as_str);

                if let (Some(pattern), Some(replacement), Some(target)) = (pattern, replacement, target) {
                    vec.push(Patch { name: patch_name.clone(), pattern: pattern.to_owned(), replacement: replacement.to_owned(), target: target.to_owned() });
                }
            }

            return Ok(Patches { vec });
        }

        Ok(Patches { vec: vec![] })
    }
}