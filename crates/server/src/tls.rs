//! TLS: the operator's certificate, or a self-signed one generated on first
//! start and pinned by installers and agents.

use std::path::Path;

use anyhow::{anyhow, Context};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::TlsInfo;

pub struct LoadedTls {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub info: TlsInfo,
}

fn info_for(cert_pem: &[u8], pinned: bool) -> anyhow::Result<TlsInfo> {
    let der = rustls_pemfile::certs(&mut &cert_pem[..])
        .next()
        .ok_or_else(|| anyhow!("no certificate in PEM"))??;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow!("parsing certificate: {e}"))?;
    let spki = cert.tbs_certificate.subject_pki.raw;
    Ok(TlsInfo {
        cert_sha256: hex::encode(Sha256::digest(&der)),
        spki_sha256_b64: base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki)),
        pinned,
    })
}

/// Load the operator's certificate and key.
pub fn load(cert: &Path, key: &Path) -> anyhow::Result<LoadedTls> {
    let cert_pem = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
    let key_pem = std::fs::read(key).with_context(|| format!("reading {}", key.display()))?;
    let info = info_for(&cert_pem, false)?;
    Ok(LoadedTls {
        cert_pem,
        key_pem,
        info,
    })
}

/// Use `<data>/tls/{cert,key}.pem`, generating them on first start.
pub fn self_signed(data_dir: &Path, names: Vec<String>) -> anyhow::Result<LoadedTls> {
    let dir = data_dir.join("tls");
    let (c, k) = (dir.join("cert.pem"), dir.join("key.pem"));
    if !c.exists() {
        std::fs::create_dir_all(&dir)?;
        let mut names = names;
        names.push("localhost".into());
        names.sort();
        names.dedup();
        let ck = rcgen::generate_simple_self_signed(names)?;
        write_private(&k, ck.key_pair.serialize_pem().as_bytes())?;
        std::fs::write(&c, ck.cert.pem())?;
        tracing::info!(path = %c.display(), "generated self-signed TLS certificate");
    }
    let cert_pem = std::fs::read(&c)?;
    let key_pem = std::fs::read(&k)?;
    let info = info_for(&cert_pem, true)?;
    Ok(LoadedTls {
        cert_pem,
        key_pem,
        info,
    })
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    std::io::Write::write_all(&mut o.open(path)?, data)
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_signed_is_stable_across_restarts() {
        let d = tempfile::tempdir().unwrap();
        let a = super::self_signed(d.path(), vec!["backup.example".into()]).unwrap();
        let b = super::self_signed(d.path(), vec![]).unwrap();
        assert_eq!(a.info.cert_sha256, b.info.cert_sha256);
        assert_eq!(a.info.cert_sha256.len(), 64);
        assert!(a.info.pinned);
    }
}
