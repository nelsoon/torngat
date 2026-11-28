//! Images: disk contents that boot disks are made from.
//!
//! An image is imported once, into a read-only, encrypted volume of the image's volume type. The
//! operator publishes *platform* images that every project can use; a project can import its own.

use serde::{Deserialize, Serialize};

use crate::Name;
use crate::meta::Object;

pub type Image = Object<ImageSpec, ImageStatus>;

pub const MAX_URL_LEN: usize = 2048;
/// Suffix of the name of the volume that holds an image.
const IMAGE_SUFFIX: &str = "-image";
/// Suffix of the name of the volume that an image is downloaded into.
const STAGING_SUFFIX: &str = "-staging";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    #[error(
        "source.url must be an https:// URL of at most {MAX_URL_LEN} printable ASCII characters, with a host and no user name, password or fragment"
    )]
    Url,
    #[error("the checksum must be lowercase hex: 64 digits for sha256, 128 for sha512")]
    Checksum,
    #[error(
        "description is longer than {} bytes or has control characters",
        crate::storage::MAX_DESCRIPTION_LEN
    )]
    Description,
    #[error("the image's name is too long for its volumes' (\"<name>-staging\")")]
    Name,
    #[error("only the description of an image can change")]
    Immutable,
}

/// The expected digest of the downloaded file, lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Checksum {
    Sha256(String),
    Sha512(String),
}

impl Checksum {
    fn validate(&self) -> Result<(), ImageError> {
        let (hex, len) = match self {
            Checksum::Sha256(h) => (h, 64),
            Checksum::Sha512(h) => (h, 128),
        };
        let ok = hex.len() == len && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(())
        } else {
            Err(ImageError::Checksum)
        }
    }
}

/// Where the image comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSource {
    /// Downloaded by a node. Only public addresses are reached, unless the operator allows others
    /// for platform images.
    pub url: String,
    pub checksum: Checksum,
}

/// Whether `url` is an absolute https URL with a host, and nothing that would be a secret
/// (credentials) or that a server never sees (a fragment). The node parses it again and checks
/// where it leads.
fn valid_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if url.len() > MAX_URL_LEN || !url.bytes().all(|b| b.is_ascii_graphic()) || url.contains('#') {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        // An IPv6 literal has colons of its own.
        Some((h, port)) if !port.contains(']') => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            h
        }
        _ => authority,
    };
    !host.is_empty() && !authority.contains('@') && !host.contains('%')
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSpec {
    pub source: ImageSource,
    /// Where the image is kept. Boot disks made from it can be of any type.
    pub volume_type: Name,
    #[serde(default)]
    pub description: String,
}

impl ImageSpec {
    pub fn validate(&self) -> Result<(), ImageError> {
        if !valid_url(&self.source.url) {
            return Err(ImageError::Url);
        }
        self.source.checksum.validate()?;
        if self.description.len() > crate::storage::MAX_DESCRIPTION_LEN
            || self.description.chars().any(crate::is_hidden)
        {
            return Err(ImageError::Description);
        }
        Ok(())
    }

    /// Whether an image may change from `self` to `new`: only its description.
    pub fn validate_update(&self, new: &Self) -> Result<(), ImageError> {
        new.validate()?;
        if (&self.source, &self.volume_type) != (&new.source, &new.volume_type) {
            return Err(ImageError::Immutable);
        }
        Ok(())
    }
}

/// The volume that holds the image `image`.
pub fn image_volume(image: &Name) -> Result<Name, ImageError> {
    Name::new(format!("{image}{IMAGE_SUFFIX}")).map_err(|_| ImageError::Name)
}

/// The volume that the image `image` is downloaded into.
pub fn staging_volume(image: &Name) -> Result<Name, ImageError> {
    Name::new(format!("{image}{STAGING_SUFFIX}")).map_err(|_| ImageError::Name)
}

/// The name of the image that the volume `volume` holds or stages, if it is named like one.
pub fn image_of(volume: &Name) -> Option<Name> {
    let v = volume.as_str();
    let image = v
        .strip_suffix(IMAGE_SUFFIX)
        .or_else(|| v.strip_suffix(STAGING_SUFFIX))?;
    Name::new(image).ok()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImagePhase {
    /// Waits for a node.
    #[default]
    Pending,
    Importing,
    /// Can be used.
    Ready,
    /// See `message`. Delete the image and make it again.
    Failed,
    Deleting,
}

/// Detected from the file's content, never from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    Raw,
    Qcow2,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageStatus {
    #[serde(default)]
    pub phase: ImagePhase,
    /// Operator's view; not for tenants. The node that imports the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<Name>,
    /// Size of the file to download, from the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ImageFormat>,
    /// Size of the disk that the image holds: boot disks made from it are at least this big.
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(url: &str) -> ImageSpec {
        ImageSpec {
            source: ImageSource {
                url: url.into(),
                checksum: Checksum::Sha256("0".repeat(64)),
            },
            volume_type: Name::new("fast").unwrap_or_else(|e| unreachable!("{e}")),
            description: String::new(),
        }
    }

    #[test]
    fn urls() {
        for ok in [
            "https://cloud.example/debian-13-genericcloud-amd64.qcow2",
            "https://cloud.example:8443/a?b=c",
            "https://10.0.0.1/x",
            "https://[2001:db8::1]/x",
            "https://[2001:db8::1]:443/x",
            "https://h",
        ] {
            assert_eq!(spec(ok).validate(), Ok(()), "{ok}");
        }
        let long = format!("https://h/{}", "a".repeat(MAX_URL_LEN));
        for bad in [
            "http://cloud.example/x",
            "file:///etc/passwd",
            "https://",
            "https:///x",
            "https://user:pw@cloud.example/x",
            "https://user@cloud.example/x",
            "https://cloud.example/x#frag",
            "https://cloud.example/a b",
            "https://cloud.example:/x",
            "https://cloud.example:ab/x",
            "https://[fe80::1%25eth0]/x",
            "https://cloud.example/\u{e9}",
            "HTTPS://cloud.example/x",
            &long,
        ] {
            assert_eq!(spec(bad).validate(), Err(ImageError::Url), "{bad}");
        }
    }

    #[test]
    fn checksums() {
        let with = |c| ImageSpec {
            source: ImageSource {
                url: "https://h/x".into(),
                checksum: c,
            },
            ..spec("https://h/x")
        };
        assert_eq!(with(Checksum::Sha512("ab".repeat(64))).validate(), Ok(()));
        for bad in [
            Checksum::Sha256("0".repeat(63)),
            Checksum::Sha256("0".repeat(128)),
            Checksum::Sha256("A".repeat(64)),
            Checksum::Sha512("0".repeat(64)),
            Checksum::Sha512("g".repeat(128)),
        ] {
            assert_eq!(with(bad).validate(), Err(ImageError::Checksum));
        }
        let json: Checksum = serde_json::from_str(&format!(r#"{{"sha256":"{}"}}"#, "a".repeat(64)))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(json, Checksum::Sha256("a".repeat(64)));
    }

    #[test]
    fn only_the_description_changes() {
        let a = spec("https://h/x");
        let mut b = a.clone();
        b.description = "Debian 13".into();
        assert_eq!(a.validate_update(&b), Ok(()));
        let mut c = a.clone();
        c.source.url = "https://h/y".into();
        assert_eq!(a.validate_update(&c), Err(ImageError::Immutable));
        let mut d = a.clone();
        d.volume_type = Name::new("slow").unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(a.validate_update(&d), Err(ImageError::Immutable));
        let mut e = a.clone();
        e.description = "a\u{202e}b".into();
        assert_eq!(a.validate_update(&e), Err(ImageError::Description));
    }

    #[test]
    fn volume_names() {
        let n = |s: &str| Name::new(s).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(image_volume(&n("debian")), Ok(n("debian-image")));
        assert_eq!(staging_volume(&n("debian")), Ok(n("debian-staging")));
        let long = n(&"a".repeat(63));
        assert_eq!(staging_volume(&long), Err(ImageError::Name));
        assert_eq!(image_of(&n("debian-image")), Some(n("debian")));
        assert_eq!(image_of(&n("debian-staging")), Some(n("debian")));
        assert_eq!(image_of(&n("a-staging-image")), Some(n("a-staging")));
        assert_eq!(image_of(&n("debian")), None);
        assert_eq!(image_of(&n("a--image")), None);
    }
}
