use age::{secrecy::ExposeSecret, Decryptor, Encryptor};
use std::env;
use std::io::{self, Read, Write};
use std::str::FromStr;

// Additional setup for file serialization and commits
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

const KEYS_FILE_LOCATION: &str = "../funkeys_pke.txt";
const KEYS_FILE_ENV: &str = "DEADDROP_LEGACY_AGE_KEYS_FILE";

pub type EncPublicKey = age::x25519::Recipient;
pub type EncPrivateKey = age::x25519::Identity;

/// Generate a fresh keypair without reading or writing the legacy key file.
pub fn generate_key_pair() -> (EncPrivateKey, EncPublicKey) {
    let identity = EncPrivateKey::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

/// Encrypt arbitrary bytes using a recipient's public key
pub fn encrypt_data(data: &[u8], recipient: &EncPublicKey) -> Vec<u8> {
    let encryptor = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .expect("failed to create encryptor");
    let mut encrypted = vec![];

    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .expect("encryption setup failed");
    writer.write_all(data).expect("encryption failed");
    writer.finish().expect("finalizing encryption failed");

    encrypted
}

/// Decrypt bytes using your private identity
pub fn decrypt_data(encrypted: &[u8], identity: &EncPrivateKey) -> Vec<u8> {
    let decryptor = Decryptor::new(encrypted).expect("failed to parse encrypted data");
    let mut reader = match decryptor {
        Decryptor::Recipients(d) => d
            .decrypt(std::iter::once(&*identity as &dyn age::Identity))
            .expect("decryption setup failed"),
        _ => panic!("unsupported decryptor variant"),
    };

    let mut decrypted = vec![];
    reader
        .read_to_end(&mut decrypted)
        .expect("decryption failed");

    decrypted
}

pub fn encrypt_to_hex(data: &[u8], recipient: &EncPublicKey) -> String {
    let encrypted = encrypt_data(data, recipient);
    hex::encode(encrypted)
}

pub fn decrypt_from_hex(encrypted_hex: &str, identity: &EncPrivateKey) -> Vec<u8> {
    let encrypted = hex::decode(encrypted_hex).expect("failed to decode hex");
    decrypt_data(&encrypted, identity)
}

/// Generate a new X25519 identity (private key) and its corresponding public key
pub fn key_gen() -> (EncPrivateKey, EncPublicKey) {
    let path = legacy_keys_path();
    key_gen_at(&path).unwrap_or_else(|error| {
        panic!(
            "failed to load legacy AGE keys at {}: {error}",
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

fn key_gen_at(path: &Path) -> Result<(EncPrivateKey, EncPublicKey), String> {
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

    let generated = generate_key_pair();
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

/// Atomically publish a complete mode-0600 key file without replacing an
/// existing receiver identity. Returns false when another process won the race.
fn write_keys_to_file_new(path: &Path, sk: &EncPrivateKey, pk: &EncPublicKey) -> io::Result<bool> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut random = [0_u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
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
        writeln!(file, "{}", sk_to_string(sk))?;
        writeln!(file, "{}", pk_to_string(pk))?;
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

/// Read keys from file
fn read_keys_from_file(path: &Path) -> io::Result<(EncPrivateKey, EncPublicKey)> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let mut lines = contents.lines();
    let sk_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing private key line"))?;
    let pk_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing public key line"))?;

    let sk = try_sk_from_string(sk_line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let pk = try_pk_from_string(pk_line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok((sk, pk))
}

/// Convert public key to string (e.g., "age1xyz...")
pub fn pk_to_string(pk: &EncPublicKey) -> String {
    pk.to_string()
}

/// Parse public key from string
pub fn pk_from_string(s: &str) -> EncPublicKey {
    try_pk_from_string(s).expect("invalid public key string")
}

pub fn try_pk_from_string(s: &str) -> Result<EncPublicKey, String> {
    EncPublicKey::from_str(s).map_err(|error| format!("invalid public key string: {error}"))
}

/// Convert a private AGE X25519 identity to its standard string form.
pub fn sk_to_string(sk: &EncPrivateKey) -> String {
    sk.to_string().expose_secret().clone()
}

/// Parse private key (identity) from string
pub fn sk_from_string(s: &str) -> EncPrivateKey {
    try_sk_from_string(s).expect("invalid private key string")
}

pub fn try_sk_from_string(s: &str) -> Result<EncPrivateKey, String> {
    EncPrivateKey::from_str(s).map_err(|error| format!("invalid private key string: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen() {
        let (_private_key, public_key) = generate_key_pair();
        assert!(!public_key.to_string().is_empty());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (private_key, public_key) = generate_key_pair();
        let data = b"Hello, world!";

        let encrypted = encrypt_data(data, &public_key);
        let decrypted = decrypt_data(&encrypted, &private_key);

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_hex() {
        let (private_key, public_key) = generate_key_pair();
        let data = b"Hello, world!";

        let encrypted_hex = encrypt_to_hex(data, &public_key);
        let decrypted = decrypt_from_hex(&encrypted_hex, &private_key);

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn concurrent_legacy_key_creation_converges_on_one_identity() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let directory = std::env::temp_dir().join(format!(
            "deaddrop-age-key-race-{}-{}",
            std::process::id(),
            hex::encode(rand::random::<[u8; 8]>())
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = Arc::new(directory.join("keys.txt"));
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let (secret, public) = key_gen_at(&path).unwrap();
                    (sk_to_string(&secret), pk_to_string(&public))
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
