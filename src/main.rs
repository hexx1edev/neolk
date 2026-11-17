mod device;
mod image;
mod patcher;
mod cert;

use device::{Device, Patches};
use image::LkImage;
use std::{io::ErrorKind, path::Path};
use patcher::Patcher;

use crate::{cert::CertBypass, device::Cert};

const VERSION: &str = "0.1.0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--> neolk v{} by hexx1edev", VERSION);

    let config = std::fs::read_to_string("device.toml")?;
    let device = Device::new(config.as_str())?;

    println!("-> Device name: {}", device.name);

    let patches_path = Path::new("patches.toml");
    
    if !patches_path.is_file() {
        println!("--> No patches found, nothing to do");
        return Ok(());
    }

    let patches_text = std::fs::read_to_string(patches_path)?;
    let patches = Patches::new(patches_text.as_str())?;

    if patches.vec.is_empty() {
        println!("--> No patches found, nothing to do");
        return Ok(());
    }

    println!("-> Opening LK image");
    let mut image = LkImage::open(device.binary.as_str())?;

    println!("-> Applying {} patches", patches.vec.len());

    for patch in &patches.vec {
        Patcher::apply(&mut image, patch)?;
        println!("--> Applied {} on {}", patch.name, patch.target);
    }

    let result = std::fs::create_dir("build");
    if let Err(e) = result {
        if e.kind() != ErrorKind::AlreadyExists {
            Err(e)?
        }
    }

    if device.cert == Cert::Override {
        println!("-> Applying override cert bypass");

        let bypass = CertBypass::Override;
        bypass.bypass(&mut image)?;
    }

    println!("-> Saving patched image");

    image.write("build/lk.img")?;

    Ok(())
}
