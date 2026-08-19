use crate::types::{PublicKey, PublicParams, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

// key file location
const KEYS_FILE_LOCATION: &str = "../funkeys.txt";
const KEYS_FILE_ENV: &str = "DEADDROP_LEGACY_OMR_KEYS_FILE";

use crate::types::*;

pub fn gen_param(lambda: usize, epsilon_p: f64, epsilon_n: f64) -> PublicParams {
    PublicParams {
        lambda,
        epsilon_p,
        epsilon_n,
    }
}

fn generate_random_32_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn generate_key_pair(_pp: &PublicParams) -> (SecretKey, PublicKey) {
    let sk = SecretKey {
        sk_bytes: generate_random_32_bytes().to_vec(),
    };
    let random_bytes = generate_random_32_bytes();
    // For simplicity, use the same random bytes for both public keys

    let pk = PublicKey {
        pk_clue: random_bytes.to_vec(),
        pk_detect: random_bytes.to_vec(),
    };

    (sk, pk)
}

pub fn keygen(pp: &PublicParams) -> (SecretKey, PublicKey) {
    let path = legacy_keys_path();
    keygen_at(pp, &path).unwrap_or_else(|error| {
        panic!(
            "failed to load legacy OMR keys at {}: {error}",
            path.display()
        )
    })
}

fn legacy_keys_path() -> PathBuf {
    env::var_os(KEYS_FILE_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(KEYS_FILE_LOCATION))
}

fn keygen_at(pp: &PublicParams, path: &Path) -> Result<(SecretKey, PublicKey), String> {
    match read_keys_from_file(path) {
        Ok(keys) => return Ok(keys),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "refusing to replace unreadable key file {}: {error}",
                path.display()
            ));
        }
    }

    let generated = generate_key_pair(pp);
    match write_keys_to_file_new(path, &generated.0, &generated.1) {
        Ok(true) => Ok(generated),
        Ok(false) => read_keys_from_file(path).map_err(|error| {
            format!(
                "failed to read atomically published key file {}: {error}",
                path.display()
            )
        }),
        Err(error) => Err(format!("failed to publish {}: {error}", path.display())),
    }
}

fn write_keys_to_file_new(path: &Path, sk: &SecretKey, pk: &PublicKey) -> io::Result<bool> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temp_path = path.with_extension(format!("tmp-{}", hex::encode(random)));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| -> io::Result<()> {
        let mut file = options.open(&temp_path)?;
        writeln!(file, "{}", encode_sk_to_hex(sk))?;
        writeln!(file, "{}", encode_pk_clue_to_hex(&pk.pk_clue))?;
        writeln!(file, "{}", encode_pk_detect_to_hex(&pk.pk_detect))?;
        file.sync_all()
    })();
    if let Err(error) = write_result {
        return Err(cleanup_error(&temp_path, parent, error));
    }

    let linked = fs::hard_link(&temp_path, path);
    match linked {
        Ok(()) => {
            if let Err(error) = sync_directory(parent) {
                return Err(cleanup_error(&temp_path, parent, error));
            }
            remove_temp(&temp_path, parent)?;
            Ok(true)
        }
        Err(error) => {
            let already_exists = error.kind() == io::ErrorKind::AlreadyExists;
            if let Err(cleanup) = remove_temp(&temp_path, parent) {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; additionally failed to remove private-key temporary file {}: {cleanup}",
                        temp_path.display()
                    ),
                ));
            }
            if already_exists {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

fn cleanup_error(temp_path: &Path, parent: &Path, error: io::Error) -> io::Error {
    match remove_temp(temp_path, parent) {
        Ok(()) => error,
        Err(cleanup) => io::Error::new(
            error.kind(),
            format!(
                "{error}; additionally failed to remove private-key temporary file {}: {cleanup}",
                temp_path.display()
            ),
        ),
    }
}

fn remove_temp(temp_path: &Path, parent: &Path) -> io::Result<()> {
    match fs::remove_file(temp_path) {
        Ok(()) => sync_directory(parent),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn read_keys_from_file(path: &Path) -> io::Result<(SecretKey, PublicKey)> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let mut lines = contents.lines();
    let sk_hex = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing secret key line"))?;
    let clue_hex = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing clue key line"))?;
    let detect_hex = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing detect key line"))?;

    let invalid = |error: String| io::Error::new(io::ErrorKind::InvalidData, error);
    let sk = decode_sk_from_hex(sk_hex).map_err(&invalid)?;
    let pk_clue = decode_pk_clue_from_hex(clue_hex).map_err(&invalid)?;
    let pk_detect = decode_pk_detect_from_hex(detect_hex).map_err(invalid)?;

    let pk = PublicKey { pk_clue, pk_detect };

    Ok((sk, pk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn concurrent_legacy_key_creation_converges_on_one_keyset() {
        let directory = std::env::temp_dir().join(format!(
            "deaddrop-omr-key-race-{}-{}",
            std::process::id(),
            hex::encode(rand::random::<[u8; 8]>())
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = Arc::new(directory.join("keys.txt"));
        let barrier = Arc::new(Barrier::new(8));
        let pp = Arc::new(gen_param(128, 0.1, 0.1));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                let pp = Arc::clone(&pp);
                thread::spawn(move || {
                    barrier.wait();
                    let (secret, public) = keygen_at(&pp, &path).unwrap();
                    (
                        encode_sk_to_hex(&secret),
                        encode_pk_clue_to_hex(&public.pk_clue),
                        encode_pk_detect_to_hex(&public.pk_detect),
                    )
                })
            })
            .collect();
        let keys: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        let first = &keys[0];
        assert!(keys.iter().all(|keyset| keyset == first));
        fs::remove_dir_all(directory).unwrap();
    }
}
