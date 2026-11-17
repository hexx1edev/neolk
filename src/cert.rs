use crate::image::{LkError, LkImage};
use sha2::{Digest, Sha256};
use std::fmt;

const IMAGE_HASH_ALIGNMENT: usize = 16;
const IMAGE_HASH_INDEX: usize = 10;
const HEADER_HASH_INDEX: usize = 14;
const IMAGE_HASH_OID_INDEX: usize = IMAGE_HASH_INDEX - 1;
const HEADER_HASH_OID_INDEX: usize = HEADER_HASH_INDEX - 1;

#[derive(Debug)]
pub enum CertError {
    Image(LkError),
    InvalidDer(&'static str),
}

impl From<LkError> for CertError {
    fn from(error: LkError) -> Self {
        Self::Image(error)
    }
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(error) => write!(f, "{error}"),
            Self::InvalidDer(message) => write!(f, "invalid cert2 DER: {message}"),
        }
    }
}

impl std::error::Error for CertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Image(error) => Some(error),
            Self::InvalidDer(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
struct DerTlv<'a> {
    tag: u8,
    encoded: &'a [u8],
    content: &'a [u8],
}

struct Cert2<'a> {
    image_oid: &'a [u8],
    header_oid: &'a [u8],
    image_hash: [u8; 32],
    header_hash: [u8; 32],
}

pub enum CertBypass {
    Override,
}

impl CertBypass {
    pub fn bypass(self, image: &mut LkImage) -> Result<(), CertError> {
        for partition in image.partitions.values_mut() {
            let Some(cert2_index) = partition
                .certs
                .iter()
                .position(|cert| cert.header.name == "cert2")
            else {
                continue;
            };

            let original_cert2 = partition.certs[cert2_index].data.clone();
            let Ok(cert2) = Self::parse_cert2(&original_cert2) else {
                // Skip already exploited cert2
                continue;
            };

            let header = LkImage::build_header(partition)?;
            let header_hash = Self::sha256(&header);
            let image_hash = Self::image_hash(&partition.data);

            if cert2.header_hash == header_hash && cert2.image_hash == image_hash {
                continue;
            }

            println!("--> Appending override block to {}'s cert2", partition.header.name);

            let override_block = Self::build_override_block(
                cert2.header_oid,
                cert2.image_oid,
                &header_hash,
                &image_hash,
            );

            let cert2 = &mut partition.certs[cert2_index];
            cert2.data = override_block;
            cert2.data.extend_from_slice(&original_cert2);
            cert2.header.data_size = cert2.data.len() as u64;
        }

        Ok(())
    }

    fn parse_cert2(raw: &[u8]) -> Result<Cert2<'_>, CertError> {
        let (outer, consumed) = Self::parse_tlv(raw)?;
        if consumed != raw.len() || outer.tag != 0x30 {
            return Err(CertError::InvalidDer("expected one outer sequence"));
        }

        let outer_fields = Self::parse_children(outer.content)?;
        let signed = *outer_fields
            .first()
            .ok_or(CertError::InvalidDer("missing signed sequence"))?;
        if signed.tag != 0x30 {
            return Err(CertError::InvalidDer("expected signed sequence"));
        }

        let fields = Self::parse_children(signed.content)?;
        let image_oid = *fields
            .get(IMAGE_HASH_OID_INDEX)
            .ok_or(CertError::InvalidDer("missing image hash OID"))?;
        let image_hash = *fields
            .get(IMAGE_HASH_INDEX)
            .ok_or(CertError::InvalidDer("missing image hash"))?;
        let header_oid = *fields
            .get(HEADER_HASH_OID_INDEX)
            .ok_or(CertError::InvalidDer("missing header hash OID"))?;
        let header_hash = *fields
            .get(HEADER_HASH_INDEX)
            .ok_or(CertError::InvalidDer("missing header hash"))?;

        if image_oid.tag != 0x06 || header_oid.tag != 0x06 {
            return Err(CertError::InvalidDer("hash OID has the wrong tag"));
        }

        Ok(Cert2 {
            image_oid: image_oid.encoded,
            header_oid: header_oid.encoded,
            image_hash: Self::parse_hash(image_hash)?,
            header_hash: Self::parse_hash(header_hash)?,
        })
    }

    fn parse_hash(value: DerTlv<'_>) -> Result<[u8; 32], CertError> {
        if value.tag != 0x03 || value.content.len() != 33 || value.content[0] != 0 {
            return Err(CertError::InvalidDer(
                "expected a 256-bit byte-aligned BIT STRING",
            ));
        }

        value.content[1..]
            .try_into()
            .map_err(|_| CertError::InvalidDer("invalid SHA-256 length"))
    }

    fn build_override_block(
        header_oid: &[u8],
        image_oid: &[u8],
        header_hash: &[u8; 32],
        image_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(header_oid);
        Self::write_bit_string(&mut content, header_hash);
        content.extend_from_slice(image_oid);
        Self::write_bit_string(&mut content, image_hash);

        let mut override_block = vec![0xa0];
        Self::write_length(&mut override_block, content.len());
        override_block.extend_from_slice(&content);
        override_block
    }

    fn write_bit_string(output: &mut Vec<u8>, hash: &[u8; 32]) {
        output.extend_from_slice(&[0x03, 0x21, 0x00]);
        output.extend_from_slice(hash);
    }

    fn write_length(output: &mut Vec<u8>, length: usize) {
        if length < 0x80 {
            output.push(length as u8);
            return;
        }

        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|&byte| byte != 0).unwrap();
        output.push(0x80 | (bytes.len() - first) as u8);
        output.extend_from_slice(&bytes[first..]);
    }

    fn parse_tlv(input: &[u8]) -> Result<(DerTlv<'_>, usize), CertError> {
        let tag = *input.first().ok_or(CertError::InvalidDer("missing tag"))?;
        let mut tag_len = 1;

        if tag & 0x1f == 0x1f {
            loop {
                let byte = *input
                    .get(tag_len)
                    .ok_or(CertError::InvalidDer("truncated high-tag number"))?;
                tag_len += 1;
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }

        let first_length = *input
            .get(tag_len)
            .ok_or(CertError::InvalidDer("missing length"))?;
        let (length, length_len) = if first_length < 0x80 {
            (first_length as usize, 1)
        } else {
            let byte_count = (first_length & 0x7f) as usize;
            if byte_count == 0 || byte_count > std::mem::size_of::<usize>() {
                return Err(CertError::InvalidDer("invalid DER length"));
            }

            let length_bytes = input
                .get(tag_len + 1..tag_len + 1 + byte_count)
                .ok_or(CertError::InvalidDer("truncated length"))?;
            let length = length_bytes
                .iter()
                .fold(0_usize, |length, &byte| (length << 8) | byte as usize);

            (length, byte_count + 1)
        };

        let content_start = tag_len + length_len;
        let content_end = content_start
            .checked_add(length)
            .ok_or(CertError::InvalidDer("length overflow"))?;
        let content = input
            .get(content_start..content_end)
            .ok_or(CertError::InvalidDer("truncated value"))?;

        Ok((
            DerTlv {
                tag,
                encoded: &input[..content_end],
                content,
            },
            content_end,
        ))
    }

    fn parse_children(mut input: &[u8]) -> Result<Vec<DerTlv<'_>>, CertError> {
        let mut children = Vec::new();

        while !input.is_empty() {
            let (child, consumed) = Self::parse_tlv(input)?;
            children.push(child);
            input = &input[consumed..];
        }

        Ok(children)
    }

    fn image_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);

        let padding =
            (IMAGE_HASH_ALIGNMENT - data.len() % IMAGE_HASH_ALIGNMENT) % IMAGE_HASH_ALIGNMENT;
        hasher.update(&[0_u8; IMAGE_HASH_ALIGNMENT][..padding]);

        hasher.finalize().into()
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
}

#[cfg(test)]
mod tests {
    use super::CertBypass;
    use crate::image::LkImage;

    #[test]
    fn prepends_an_override_to_a_modified_cert2() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/template/binaries/lk.img");
        let mut image = LkImage::open(path).unwrap();
        let partition = image.partitions.get_mut("lk").unwrap();
        let cert2_index = partition
            .certs
            .iter()
            .position(|cert| cert.header.name == "cert2")
            .unwrap();
        let original_cert2 = partition.certs[cert2_index].data.clone();

        partition.data[0] ^= 1;
        CertBypass::Override.bypass(&mut image).unwrap();

        let cert2 = &image.partitions["lk"].certs[cert2_index];
        assert_eq!(cert2.data[0], 0xa0);
        assert!(cert2.data.ends_with(&original_cert2));
        assert_eq!(cert2.header.data_size as usize, cert2.data.len());
    }
}
