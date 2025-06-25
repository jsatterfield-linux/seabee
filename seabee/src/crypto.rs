// SPDX-License-Identifier: Apache-2.0
use std::{
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use clap::Args;
use openssl::{
    self,
    bn::BigNumContext,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    sign::{Signer, Verifier},
};
use strum::VariantNames;
use zerocopy::IntoBytes;

use crate::{policy::policy_file::PolicyFile, utils};

/// A key used to verify SeaBeePolicy Updates
#[derive(Debug, Clone)]
pub struct SeaBeeKey {
    // Where the key was added from, useful for printing
    added_from: PathBuf,
    /// The path on disk where this key is saved
    pub seabee_path: PathBuf,
    /// The path on disk where the signature for this key is saved
    pub sig_path: PathBuf,
    /// The digest used to sign this key
    pub sig_digest: SeaBeeDigest,
    /// The key itself, see openssl::pkey::Pkey
    pub key: PKey<Public>,
    /// The id used to identify this key
    pub id: u32,
}

impl SeaBeeKey {
    /// Create a new SeaBeeKey from a path and an id
    pub fn new_key(path: &PathBuf, id: u32) -> Result<Self> {
        utils::verify_file_has_ext(path, vec!["pem"])?;
        let key_file_bytes = utils::file_to_bytes(&path)?;
        let abs_path = utils::get_abs_path(path)?;

        Ok(Self {
            added_from: abs_path,
            seabee_path: PathBuf::new(),
            sig_path: PathBuf::new(),
            sig_digest: SeaBeeDigest::default(),
            key: PKey::public_key_from_pem(&key_file_bytes)?,
            id,
        })
    }

    /// Two SeaBeeKeys are equal if they are both RSA and have the same modulus (n)
    /// and exponent (e), or if they are both EC keys and EC_POINT_cmp returns 0.
    ///
    /// error if EC_POINT_cmp returns -1 or BN_CTX_new fails
    pub fn try_eq(&self, other: &Self) -> Result<bool> {
        if self.key.id() == Id::EC && other.key.id() == Id::EC {
            let mut ctx = BigNumContext::new()?;
            let ec_key = self.key.ec_key()?;
            return Ok(ec_key.public_key().eq(
                ec_key.group(),
                other.key.ec_key()?.public_key(),
                &mut ctx,
            )?);
        }
        if self.key.id() == Id::RSA && other.key.id() == Id::RSA {
            let our_key = self.key.rsa()?;
            let other_key = other.key.rsa()?;
            return Ok((our_key.e() == other_key.e()) && (our_key.n() == other_key.n()));
        }
        Ok(false)
    }
}

impl fmt::Display for SeaBeeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_type = match self.key.id() {
            Id::RSA => "RSA",
            Id::EC => "EC",
            _ => "Unsupported Type",
        };

        write!(
            f,
            "Added from: {}\nId: {}\nType: {}\nSize: {}",
            self.added_from.display(),
            self.id,
            key_type,
            self.key.bits()
        )
    }
}

/// Information needed to sign a policy
#[derive(Args, Debug, Clone)]
pub struct SignInfo {
    /// Path to a file to sign
    #[arg(short, long)]
    target_path: PathBuf,

    /// Path to a .pem containing the private signing key
    #[arg(short, long)]
    key_path: PathBuf,

    /// Output path for the signature
    #[arg(short, long, default_value = "signature.sign")]
    out_path: PathBuf,

    /// Message digest algorithm, overrides a digest specified in policy file.
    #[arg(short, long)]
    digest: Option<SeaBeeDigest>,
}

/// SHA3: [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
/// SHA2: [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
#[derive(
    clap::ValueEnum,
    Clone,
    Debug,
    Default,
    serde::Deserialize,
    serde::Serialize,
    strum_macros::FromRepr,
    strum_macros::VariantNames,
    strum_macros::AsRefStr,
)]
pub enum SeaBeeDigest {
    sha3_224 = 1,
    #[default]
    sha3_256,
    sha3_384,
    sha3_512,
    sha224,
    sha256,
    sha384,
    sha512,
}

impl TryFrom<SeaBeeDigest> for MessageDigest {
    type Error = anyhow::Error;

    fn try_from(value: SeaBeeDigest) -> std::result::Result<Self, Self::Error> {
        let name = value.as_ref().replace('_', "-");
        match MessageDigest::from_name(&name) {
            Some(d) => Ok(d),
            None => Err(anyhow!("Failed to convert '{}' to MessageDigest", name)),
        }
    }
}

impl TryFrom<u32> for SeaBeeDigest {
    type Error = anyhow::Error;

    /// Tries to match u32 to a discriminant value for a SeaBeeDigest
    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match SeaBeeDigest::from_repr(value as usize) {
            Some(digest) => Ok(digest),
            None => Err(anyhow!("Could not convert u32 '{}' to SeaBeeDigest", value)),
        }
    }
}

pub fn sign_policy(info: &SignInfo) -> Result<String> {
    // Get hash function
    let hash_func = get_digest_algorithm(&info.target_path, &info.digest)?;

    // Get the pem file contents
    utils::verify_file_has_ext(&info.key_path, vec!["pem"])?;
    let key_bytes = utils::file_to_bytes(&info.key_path)?;

    // Get pem passphrase from command line
    let passphrase = rpassword::prompt_password("Enter pem passphrase for signing key:")?;
    // Create openssl signer with hash_func and key
    // This supports algorithms besides RSA and ECDSA, but I have those listed as supported since they are common and NIST approved
    let signing_key = PKey::private_key_from_pem_passphrase(&key_bytes, passphrase.as_bytes())?;
    let mut signer = Signer::new(hash_func, &signing_key)?;
    // Get policy file contents
    let policy_bytes = utils::file_to_bytes(&info.target_path)?;
    // Sign policy
    let signature = signer.sign_oneshot_to_vec(&policy_bytes)?;
    // Output signature
    if let Err(e) = std::fs::write(&info.out_path, signature.as_bytes()) {
        Err(anyhow!(
            "Error write signature '{:?}' to file '{}'\n{e}",
            signature,
            info.out_path.display(),
        ))
    } else {
        Ok(format!(
            "Successfully wrote signature to '{}'",
            &info.out_path.display()
        ))
    }
}

/// Information needed to verify a policy.
/// Note that this is only provided for testing/debugging purposes.
#[derive(Args, Debug, Clone)]
pub struct VerifyInfoCLI {
    /// Path to a policy to verify
    #[arg(short, long)]
    pub target_path: PathBuf,

    /// Path the signature for the policy
    #[arg(short, long)]
    pub sig_path: PathBuf,

    /// Path to a pem file containing a verification key
    #[arg(short, long)]
    pub key_path: PathBuf,

    /// Message digest algorithm used to sign, overrides digest provided in policy file.
    #[arg(short, long)]
    pub digest: Option<SeaBeeDigest>,
}

/// verify a file through the cli using VerifyInfoCLI struct
pub fn verify_policy_signature_cli(info: &VerifyInfoCLI) -> Result<String> {
    let key = SeaBeeKey::new_key(&info.key_path, 0)?;
    let digest = get_digest_algorithm(&info.target_path, &info.digest)?;

    if verify_file_signature(&info.target_path, &info.sig_path, digest, &key)? {
        Ok("Verified OK".to_string())
    } else {
        Ok("Verifcation failure".to_string())
    }
}

/// verify a file given a signature, digest algorithm, and keylist
pub fn verify_file_signature(
    target_path: &Path,
    sig_path: &Path,
    digest: MessageDigest,
    key: &SeaBeeKey,
) -> Result<bool> {
    let policy_bytes = utils::file_to_bytes(&target_path)?;
    let sig_bytes = utils::file_to_bytes(&sig_path)?;

    // set up verifier
    let mut verifier = Verifier::new(digest, &key.key)?;
    // do verification
    match verifier.verify_oneshot(&sig_bytes, &policy_bytes) {
        Ok(result) => Ok(result),
        Err(e) => Err(openssl_to_anyhow_error(e)),
    }
}
fn openssl_to_anyhow_error(e: ErrorStack) -> anyhow::Error {
    let mut err_string = format!("{} openssl errors\n", e.errors().len());
    if e.errors().is_empty() {
        err_string.push_str("Maybe due to key type not matching signature type");
    }
    for err in e.errors() {
        err_string.push_str(&format!("- {:?}: {:?}", err.library(), err.reason()));
    }

    anyhow!("{}", err_string)
}

pub fn list_crypto_alg() -> String {
    let mut out = String::new();
    out.push_str("Digital Signature Algorithms: RSA, ECDSA\n");
    out.push_str(&format!(
        "Message Digest Algorithms: {}\n",
        SeaBeeDigest::VARIANTS.join(", ")
    ));
    out.push_str("Key formats: pem");
    out
}

pub fn get_digest_algorithm(
    policy_path: &PathBuf,
    cli_digest: &Option<SeaBeeDigest>,
) -> Result<MessageDigest> {
    if cli_digest.is_some() {
        Ok(cli_digest.clone().unwrap().try_into()?)
    } else if let Ok(policy) = PolicyFile::from_path(policy_path) {
        Ok(policy.digest.try_into()?)
    } else {
        // Use default digest when one is not specified
        Ok(SeaBeeDigest::default().try_into()?)
    }
}
