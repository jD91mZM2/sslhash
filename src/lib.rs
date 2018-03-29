#[macro_use] extern crate failure;
extern crate openssl;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sha;
use openssl::ssl::{HandshakeError, SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::{X509, X509Name};
use std::env;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::path::PathBuf;

const RSA_BITS: u32 = 3072;

/// Create a string SHA-256 hash from binary data.
pub fn sha256(data: &[u8]) -> String {
    use std::fmt::Write;
    let hash = sha::sha256(data);

    let mut string = String::with_capacity(hash.len() * 2);
    for byte in &hash {
        write!(string, "{:02X}", byte).unwrap();
    }
    string
}

#[derive(Debug, Fail)]
pub enum AcceptorError {
    #[fail(display = "openssl error: {}", _0)]
    OpensslError(#[cause] ErrorStack),
    #[fail(display = "io error: {}", _0)]
    IoError(#[cause] IoError),
    #[fail(display = "failed to get current exe directory: no parent")]
    ExeNoParent
}
impl From<ErrorStack> for AcceptorError {
    fn from(err: ErrorStack) -> Self { AcceptorError::OpensslError(err) }
}
impl From<IoError> for AcceptorError {
    fn from(err: IoError) -> Self { AcceptorError::IoError(err) }
}

enum CacheDir {
    ExeDir,
    Path(PathBuf)
}
/// Build an SslAcceptor with a generated (and by default cached) key
pub struct AcceptorBuilder {
    bits: u32,
    cache_dir: Option<CacheDir>
}
impl Default for AcceptorBuilder {
    fn default() -> Self {
        Self {
            bits: RSA_BITS,
            cache_dir: Some(CacheDir::ExeDir)
        }
    }
}
impl AcceptorBuilder {
    /// Set the number of RSA key bits. Default: 3072
    pub fn set_bits(mut self, bits: u32) -> Self {
        self.bits = bits;
        self
    }
    /// Set the cache directory or disable caching. Default is the same directory as the EXE.
    pub fn set_cache_dir(mut self, cache_dir: Option<PathBuf>) -> Self {
        self.cache_dir = cache_dir.map(CacheDir::Path);
        self
    }
    /// Build a random PKey object as well as a hash of the public key
    pub fn build_pkey(self) -> Result<(PKey<Private>, String), AcceptorError> {
        // Resolve cache variable
        let cache = match self.cache_dir {
            Some(CacheDir::ExeDir) =>
                Some(env::current_exe()?
                    .canonicalize()?
                    .parent()
                    .ok_or(AcceptorError::ExeNoParent)?
                    .join("key.pem")),
            Some(CacheDir::Path(mut path)) => {
                path.push("key.pem");
                Some(path)
            },
            None => None,
        };

        // Attempt to read cache
        let rsa = if let Some(ref cache) = cache {
            let mut bytes = Vec::new();
            match File::open(cache) {
                Ok(mut file) => {
                    file.read_to_end(&mut bytes)?;
                    Some(Rsa::private_key_from_pem(&bytes)?)
                },
                Err(ref err) if err.kind() == IoErrorKind::NotFound => None,
                Err(err) => return Err(err.into())
            }
        } else { None };

        // In case cache does not exist
        let rsa = match rsa {
            Some(rsa) => rsa,
            None => {
                let rsa = Rsa::generate(self.bits)?;
                if let Some(ref cache) = cache {
                    File::create(cache)?.write_all(&rsa.private_key_to_pem()?)?;
                }
                rsa
            }
        };
        let hash = sha256(&rsa.public_key_to_pem()?);
        Ok((PKey::from_rsa(rsa)?, hash))
    }
    /// Build a SslAcceptor with the output of `build_pkey`
    pub fn build(self) -> Result<(SslAcceptor, String), AcceptorError> {
        // Generate key
        let (pkey, hash) = self.build_pkey()?;

        // Generate certificate
        let mut builder = X509::builder()?;
        builder.set_serial_number(&*BigNum::from_u32(1)?.to_asn1_integer()?)?;
        builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;
        builder.set_not_after(&*Asn1Time::days_from_now(365)?)?;
        builder.set_pubkey(&pkey)?;
        builder.set_issuer_name(&*{
            let mut builder = X509Name::builder()?;
            builder.append_entry_by_text("C", "..")?;
            builder.append_entry_by_text("O", ".....")?;
            builder.append_entry_by_text("CN", "localhost")?;

            builder.build()
        })?;
        builder.sign(&pkey, MessageDigest::sha256())?;
        let cert = builder.build();

        // Create acceptor
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key(&pkey)?;
        builder.set_certificate(&cert)?;
        Ok((builder.build(), hash))
    }
}

/// As a client, connect to the server and compare the public key hash with `cmp_hash`
pub fn connect<S: Read + Write>(connector: &SslConnector, stream: S, cmp_hash: String)
    -> Result<SslStream<S>, HandshakeError<S>>
{
    let mut configure = connector.configure()?
        .use_server_name_indication(false)
        .verify_hostname(false);
    configure.set_verify_callback(SslVerifyMode::PEER, move |_, cert| {
        if let Some(cert) = cert.current_cert() {
            if let Ok(pkey) = cert.public_key() {
                if let Ok(pem) = pkey.public_key_to_pem() {
                    let hash = sha256(&pem);
                    return hash.trim().eq_ignore_ascii_case(&cmp_hash)
                }
            }
        }
        false
    });
    configure.connect("", stream)
}
