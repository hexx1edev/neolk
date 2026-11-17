//! MTK's MKIMG image management

use indexmap::IndexMap;
use std::fmt;

#[derive(Debug)]
pub enum LkError {
    Io(std::io::Error),
    Truncated { offset: usize },
    BadMagic { offset: usize, found: u32 },
    InvalidHeaderSize(u32),
    InvalidAlignment(u32),
    InvalidName,
    IntegerOverflow,
    CertBeforePartition,
}

impl From<std::io::Error> for LkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for LkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LkError::Io(error) => write!(f, "I/O error: {error}"),

            LkError::Truncated { offset } => {
                write!(f, "truncated LK image at offset 0x{offset:x}")
            }

            LkError::BadMagic { offset, found } => {
                write!(f, "invalid LK magic 0x{found:08x} at offset 0x{offset:x}")
            }

            LkError::InvalidHeaderSize(size) => {
                write!(f, "invalid LK header size: {size}")
            }

            LkError::InvalidAlignment(alignment) => {
                write!(f, "invalid LK alignment: {alignment}")
            }

            LkError::InvalidName => write!(f, "invalid LK partition name"),

            LkError::IntegerOverflow => {
                write!(f, "LK image offset or size overflow")
            }

            LkError::CertBeforePartition => {
                write!(f, "certificate encountered before its partition")
            }
        }
    }
}

impl std::error::Error for LkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LkError::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct LkImage {
    pub partitions: IndexMap<String, LkSubimage>,
    pub version: Option<LkVersion>,
    trailing_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LkVersion {
    V1,
    V2,
}

#[derive(Debug, Clone)]
pub struct LkSubimage {
    pub header: LkHeader,
    pub data: Vec<u8>,
    pub certs: Vec<LkSubimage>,
    pub padding: Vec<u8>,
    pub offset: u64,
    pub total_size: usize,
}

#[derive(Debug, Clone)]
pub struct LkHeader {
    pub magic: u32,
    pub data_size: u64,
    pub name: String,
    pub load_addr: u64,
    pub mode: u32,
    pub extended: Option<LkExtendedHeader>,
    pub padding: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LkExtendedHeader {
    pub header_size: u32,
    pub version: u32,
    pub image_type: LkSubimageType,
    pub alignment: u32,
    pub image_list_end: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LkSubimageType {
    pub id: u8,
    pub reserved: [u8; 2],
    pub group: u8,
}

impl LkSubimageType {
    pub const AP_BINARY: Self = Self {
        id: 0,
        reserved: [0; 2],
        group: 0,
    };

    pub const CERT2: Self = Self {
        id: 2,
        reserved: [0; 2],
        group: 2,
    };
}

fn u32_le(bytes: &[u8], offset: usize) -> Result<u32, LkError> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or(LkError::Truncated { offset })?;

    Ok(u32::from_le_bytes(field.try_into().unwrap()))
}

impl LkImage {
    pub fn open(path: &str) -> Result<LkImage, LkError> {
        let mut image = LkImage {
            partitions: IndexMap::new(),
            version: None,
            trailing_data: vec![],
        };

        let bytes: Vec<u8> = std::fs::read(path)?;

        let _ = Self::read_next(&mut image, &bytes, 0)?;

        image.partitions.reverse(); // my parser is shitty so this simple workaround makes subimages remain their original order

        Ok(image)
    }

    fn read_next(
        image: &mut LkImage,
        bytes: &Vec<u8>,
        offset: usize,
    ) -> Result<Option<LkSubimage>, LkError> {
        let magic = 0x58881688;
        let start = u32_le(bytes, offset)?;

        if start != magic {
            return Err(LkError::BadMagic {
                offset,
                found: start,
            });
        }

        let mut header = LkHeader {
            data_size: 0,
            magic: 0,
            name: String::new(),
            load_addr: 0,
            mode: 0,
            extended: None,
            padding: vec![],
        };

        let data_size_low = u32_le(bytes, offset + 4)?;
        let mut data_size = data_size_low as u64;
        let name_bytes = bytes
            .get(offset + 0x08..offset + 0x28)
            .ok_or(LkError::Truncated { offset })?;

        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
        let name = std::str::from_utf8(&name_bytes[..name_end])
            .map_err(|_| LkError::InvalidName)?
            .to_owned();

        let load_addr_low = u32_le(bytes, offset + 0x28)?;
        let mut load_addr = load_addr_low as u64;
        let mode = u32_le(bytes, offset + 0x2C)?;

        header.magic = magic;
        header.name = name;
        header.mode = mode;

        let ext_magic = 0x58891689;
        let ext = u32_le(bytes, offset + 0x30)?;

        let mut actual_header_size: usize = 512;
        let mut alignment = 8;

        if ext == ext_magic {
            let mut extended = LkExtendedHeader {
                alignment: 0,
                header_size: 0,
                version: 0,
                image_type: LkSubimageType::AP_BINARY,
                image_list_end: false,
            };

            let header_size = u32_le(bytes, offset + 0x34)?;
            let header_version = u32_le(bytes, offset + 0x38)?;
            let image_type = LkSubimageType {
                id: bytes[offset + 0x3C],
                reserved: [bytes[offset + 0x3D], bytes[offset + 0x3E]],
                group: bytes[offset + 0x3F],
            };

            let image_list_end = u32_le(bytes, offset + 0x40)? == 1;
            alignment = u32_le(bytes, offset + 0x44)?;

            let data_size_high = u32_le(bytes, offset + 0x48)?;
            let load_addr_high = u32_le(bytes, offset + 0x4C)?;

            extended.alignment = alignment;
            extended.header_size = header_size;
            extended.version = header_version;
            extended.image_type = image_type;
            extended.image_list_end = image_list_end;

            data_size = data_size | ((data_size_high as u64) << 32);
            load_addr = load_addr | ((load_addr_high as u64) << 32);

            header.extended = Some(extended);

            actual_header_size = header_size as usize;
        }

        header.data_size = data_size;
        header.load_addr = load_addr;

        if actual_header_size < 512 {
            return Err(LkError::InvalidHeaderSize(actual_header_size as u32));
        }

        let data_start = offset
            .checked_add(actual_header_size)
            .ok_or(LkError::IntegerOverflow)?;
        let data_len = usize::try_from(data_size).map_err(|_| LkError::IntegerOverflow)?;
        let data_end = data_start
            .checked_add(data_len)
            .ok_or(LkError::IntegerOverflow)?;

        let data = bytes
            .get(data_start..data_end)
            .ok_or(LkError::Truncated { offset: data_start })?
            .to_vec();

        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(LkError::InvalidAlignment(alignment));
        }

        let padding_len =
            ((alignment as usize) - (data_len % (alignment as usize))) % (alignment as usize);

        let mut next_offset = data_end
            .checked_add(padding_len)
            .ok_or(LkError::IntegerOverflow)?;

        header.padding = bytes
            .get(offset + 0x50..data_start)
            .ok_or(LkError::Truncated {
                offset: offset + 0x50,
            })?
            .to_vec();

        let padding = bytes
            .get(data_end..next_offset)
            .ok_or(LkError::Truncated { offset: data_end })?
            .to_vec();

        let total_size = actual_header_size
            .checked_add(data_len)
            .and_then(|size| size.checked_add(padding_len))
            .ok_or(LkError::IntegerOverflow)?;

        let mut subimage = LkSubimage {
            header,
            data,
            certs: vec![],
            padding,
            offset: offset as u64,
            total_size,
        };

        if !subimage.is_certificate() {
            loop {
                if next_offset >= bytes.len() {
                    break;
                }

                let next = Self::read_next(image, bytes, next_offset)?;
                if let Some(next) = next
                    && next.is_certificate()
                {
                    next_offset += next.total_size;
                    subimage.certs.push(next);
                } else {
                    break;
                }
            }
            image
                .partitions
                .insert(subimage.header.name.clone(), subimage.clone());

            return Ok(None);
        } else {
            return Ok(Some(subimage));
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, LkError> {
        let mut output: Vec<u8> = Vec::new();

        for partition in self.partitions.values() {
            self.write_subimage(&mut output, partition)?;

            for cert in &partition.certs {
                self.write_subimage(&mut output, cert)?;
            }
        }

        output.extend_from_slice(&self.trailing_data);

        Ok(output)
    }

    pub fn write(&self, path: &str) -> Result<(), LkError> {
        std::fs::write(path, self.to_bytes()?)?;
        Ok(())
    }

    /// Builds the fixed-size MKIMG header used for hashing and serialization.
    pub fn build_header(image: &LkSubimage) -> Result<[u8; 512], LkError> {
        let header_size = image
            .header
            .extended
            .as_ref()
            .map_or(512, |ext| ext.header_size as usize);

        if header_size < 512 {
            return Err(LkError::InvalidHeaderSize(header_size as u32));
        }

        let reserved_size = header_size
            .checked_sub(0x50)
            .ok_or(LkError::InvalidHeaderSize(
                image
                    .header
                    .extended
                    .as_ref()
                    .map_or(512, |ext| ext.header_size),
            ))?;

        if !image.header.padding.is_empty() && image.header.padding.len() != reserved_size {
            return Err(LkError::InvalidHeaderSize(
                image
                    .header
                    .extended
                    .as_ref()
                    .map_or(512, |ext| ext.header_size),
            ));
        }

        let data_size = image.data.len() as u64;
        let mut header = [0_u8; 512];

        header[0x00..0x04].copy_from_slice(&image.header.magic.to_le_bytes());
        header[0x04..0x08].copy_from_slice(&(data_size as u32).to_le_bytes());

        let name = image.header.name.as_bytes();
        if name.len() > 32 {
            return Err(LkError::InvalidName);
        }
        header[0x08..0x08 + name.len()].copy_from_slice(name);

        header[0x28..0x2c].copy_from_slice(&(image.header.load_addr as u32).to_le_bytes());
        header[0x2c..0x30].copy_from_slice(&image.header.mode.to_le_bytes());

        if let Some(ext) = &image.header.extended {
            header[0x30..0x34].copy_from_slice(&0x5889_1689_u32.to_le_bytes());
            header[0x34..0x38].copy_from_slice(&ext.header_size.to_le_bytes());
            header[0x38..0x3c].copy_from_slice(&ext.version.to_le_bytes());
            header[0x3c] = ext.image_type.id;
            header[0x3d..0x3f].copy_from_slice(&ext.image_type.reserved);
            header[0x3f] = ext.image_type.group;
            header[0x40..0x44].copy_from_slice(&(ext.image_list_end as u32).to_le_bytes());
            header[0x44..0x48].copy_from_slice(&ext.alignment.to_le_bytes());
            header[0x48..0x4c].copy_from_slice(&((data_size >> 32) as u32).to_le_bytes());
            header[0x4c..0x50]
                .copy_from_slice(&((image.header.load_addr >> 32) as u32).to_le_bytes());
        }

        if !image.header.padding.is_empty() {
            let fixed_padding_size = image.header.padding.len().min(512 - 0x50);
            header[0x50..0x50 + fixed_padding_size]
                .copy_from_slice(&image.header.padding[..fixed_padding_size]);
        }

        Ok(header)
    }

    fn write_subimage(&self, output: &mut Vec<u8>, image: &LkSubimage) -> Result<(), LkError> {
        let header_size = image
            .header
            .extended
            .as_ref()
            .map_or(512, |ext| ext.header_size as usize);
        let alignment = image
            .header
            .extended
            .as_ref()
            .map_or(8, |ext| ext.alignment as usize);

        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(LkError::InvalidAlignment(alignment as u32));
        }

        let header = Self::build_header(image)?;
        output.extend_from_slice(&header);

        if header_size > 512 {
            if image.header.padding.is_empty() {
                output.resize(output.len() + header_size - 512, 0);
            } else {
                output.extend_from_slice(&image.header.padding[512 - 0x50..]);
            }
        }

        output.extend_from_slice(&image.data);

        let padding_size = (alignment - image.data.len() % alignment) % alignment;
        if image.padding.len() == padding_size {
            output.extend_from_slice(&image.padding);
        } else {
            output.resize(output.len() + padding_size, 0);
        }

        Ok(())
    }
}

impl LkSubimage {
    pub fn is_certificate(&self) -> bool {
        let named_as_cert = self.header.name.starts_with("cert");

        let typed_as_cert = self
            .header
            .extended
            .as_ref()
            .is_some_and(|ext| ext.image_type.group == 2);

        named_as_cert || typed_as_cert
    }
}

#[cfg(test)]
mod tests {
    use super::LkImage;

    #[test]
    fn reconstructs_template_image_without_changes() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/template/binaries/lk.img");
        let original = std::fs::read(path).unwrap();
        let image = LkImage::open(path).unwrap();

        assert_eq!(image.to_bytes().unwrap(), original);
    }
}
