//! Tag Scan variants behind one interface, so the same driver, board layout and tag derivation
//! (`tag_from_secret`) serve every scheme:
//!
//! | scheme         | library        | per-entry public value     | entry bytes |
//! |----------------|----------------|----------------------------|-------------|
//! | `x25519`       | x25519-dalek   | ephemeral X25519 key, 32 B | 48          |
//! | `x25519-awslc` | aws-lc-rs      | ephemeral X25519 key, 32 B | 48          |
//! | `mlkem512`     | aws-lc-rs      | ML-KEM-512 ciphertext, 768 B  | 784      |
//! | `mlkem768`     | aws-lc-rs      | ML-KEM-768 ciphertext, 1088 B | 1104     |
//!
//! ML-KEM entries: the sender encapsulates to the receiver's encapsulation key, giving `(ct, ss)`;
//! the entry is `ct || tag` with `tag = tag_from_secret(ss, ct, binding, info)`. The receiver
//! decapsulates every ciphertext. ML-KEM's implicit rejection returns a pseudorandom secret for a
//! ciphertext made for someone else, so the tag simply fails to match.

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_512, ML_KEM_768};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{binding_for_index, make_entry, TAG_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    X25519Dalek,
    X25519AwsLc,
    MlKem512,
    MlKem768,
}

const INFO_X25519: &[u8] = b"DeadDrop-TagScan-v1";
const INFO_MLKEM512: &[u8] = b"DeadDrop-PQTagScan-v1/ML-KEM-512";
const INFO_MLKEM768: &[u8] = b"DeadDrop-PQTagScan-v1/ML-KEM-768";

impl Scheme {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "x25519" => Some(Self::X25519Dalek),
            "x25519-awslc" => Some(Self::X25519AwsLc),
            "mlkem512" => Some(Self::MlKem512),
            "mlkem768" => Some(Self::MlKem768),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::X25519Dalek => "x25519",
            Self::X25519AwsLc => "x25519-awslc",
            Self::MlKem512 => "mlkem512",
            Self::MlKem768 => "mlkem768",
        }
    }
    /// Length of the per-entry public value (ephemeral key or KEM ciphertext).
    pub fn public_len(self) -> usize {
        match self {
            Self::X25519Dalek | Self::X25519AwsLc => 32,
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
        }
    }
    pub fn entry_len(self) -> usize {
        self.public_len() + TAG_BYTES
    }
    fn info(self) -> &'static [u8] {
        match self {
            Self::X25519Dalek | Self::X25519AwsLc => INFO_X25519,
            Self::MlKem512 => INFO_MLKEM512,
            Self::MlKem768 => INFO_MLKEM768,
        }
    }
    fn kem(self) -> &'static aws_lc_rs::kem::Algorithm {
        match self {
            Self::MlKem512 => &ML_KEM_512,
            Self::MlKem768 => &ML_KEM_768,
            _ => unreachable!("not a KEM scheme"),
        }
    }
}

/// Receiver key generation: returns (secret key bytes, public key bytes).
pub fn keygen(s: Scheme) -> (Vec<u8>, Vec<u8>) {
    match s {
        Scheme::X25519Dalek => {
            let sk = StaticSecret::random();
            let pk = PublicKey::from(&sk);
            (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
        }
        Scheme::X25519AwsLc => {
            let mut raw = [0u8; 32];
            aws_lc_rs::rand::fill(&mut raw).expect("system RNG");
            let sk = PrivateKey::from_private_key(&X25519, &raw).expect("32-byte X25519 key");
            let pk = sk.compute_public_key().expect("public key");
            (raw.to_vec(), pk.as_ref().to_vec())
        }
        Scheme::MlKem512 | Scheme::MlKem768 => {
            let dk = DecapsulationKey::generate(s.kem()).expect("ML-KEM keygen");
            let ek = dk.encapsulation_key().expect("encapsulation key");
            let skb = dk.key_bytes().expect("dk bytes").as_ref().to_vec();
            let pkb = ek.key_bytes().expect("ek bytes").as_ref().to_vec();
            (skb, pkb)
        }
    }
}

/// A recipient as seen by senders: a parsed public key.
pub enum Recipient {
    Dalek(PublicKey),
    AwsX25519(Vec<u8>),
    Kem(Scheme, EncapsulationKey),
}

impl Recipient {
    pub fn from_public(s: Scheme, pk: &[u8]) -> Self {
        match s {
            Scheme::X25519Dalek => {
                let b: [u8; 32] = pk.try_into().expect("32-byte X25519 public key");
                Self::Dalek(PublicKey::from(b))
            }
            Scheme::X25519AwsLc => {
                assert_eq!(pk.len(), 32, "32-byte X25519 public key");
                Self::AwsX25519(pk.to_vec())
            }
            Scheme::MlKem512 | Scheme::MlKem768 => {
                Self::Kem(s, EncapsulationKey::new(s.kem(), pk).expect("valid ML-KEM encapsulation key"))
            }
        }
    }

    /// Sender: one board entry for this recipient, with fresh randomness per call.
    /// Returns None for a non-contributory (low-order) X25519 recipient key.
    pub fn make_entry(&self, binding: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Dalek(pk) => make_entry(pk, binding).ok().map(|e| e.to_vec()),
            Self::AwsX25519(pk) => {
                let mut raw = [0u8; 32];
                aws_lc_rs::rand::fill(&mut raw).ok()?;
                let esk = PrivateKey::from_private_key(&X25519, &raw).ok()?;
                let epk = esk.compute_public_key().ok()?;
                let tag = agreement::agree(&esk, UnparsedPublicKey::new(&X25519, pk.as_slice()), (), |ss| {
                    Ok(crate::tag_from_secret(ss, epk.as_ref(), binding, INFO_X25519))
                })
                .ok()?;
                let mut e = epk.as_ref().to_vec();
                e.extend_from_slice(&tag);
                Some(e)
            }
            Self::Kem(s, ek) => {
                let (ct, ss) = ek.encapsulate().ok()?;
                let tag = crate::tag_from_secret(ss.as_ref(), ct.as_ref(), binding, s.info());
                let mut e = ct.as_ref().to_vec();
                e.extend_from_slice(&tag);
                Some(e)
            }
        }
    }
}

/// The receiver's secret key, parsed once.
pub enum Receiver {
    Dalek(StaticSecret),
    AwsX25519(PrivateKey),
    Kem(Scheme, DecapsulationKey),
}

impl Receiver {
    pub fn from_secret(s: Scheme, sk: &[u8]) -> Self {
        match s {
            Scheme::X25519Dalek => {
                let b: [u8; 32] = sk.try_into().expect("32-byte X25519 secret key");
                Self::Dalek(StaticSecret::from(b))
            }
            Scheme::X25519AwsLc => Self::AwsX25519(PrivateKey::from_private_key(&X25519, sk).expect("X25519 key")),
            Scheme::MlKem512 | Scheme::MlKem768 => {
                Self::Kem(s, DecapsulationKey::new(s.kem(), sk).expect("valid ML-KEM decapsulation key"))
            }
        }
    }

    pub fn scheme(&self) -> Scheme {
        match self {
            Self::Dalek(_) => Scheme::X25519Dalek,
            Self::AwsX25519(_) => Scheme::X25519AwsLc,
            Self::Kem(s, _) => *s,
        }
    }

    /// One X25519 or one decapsulation, one HKDF, one HMAC, and a constant-time tag compare.
    pub fn check(&self, entry: &[u8], binding: &[u8]) -> bool {
        let s = self.scheme();
        if entry.len() != s.entry_len() {
            return false;
        }
        let (public, tag) = entry.split_at(s.public_len());
        let expected = match self {
            Self::Dalek(sk) => return crate::check_entry(sk, entry, binding),
            Self::AwsX25519(sk) => {
                // AWS-LC rejects an all-zero (non-contributory) shared secret with an error.
                match agreement::agree(sk, UnparsedPublicKey::new(&X25519, public), (), |ss| {
                    Ok(crate::tag_from_secret(ss, public, binding, INFO_X25519))
                }) {
                    Ok(t) => t,
                    Err(()) => return false,
                }
            }
            Self::Kem(s, dk) => match dk.decapsulate(Ciphertext::from(public)) {
                Ok(ss) => crate::tag_from_secret(ss.as_ref(), public, binding, s.info()),
                Err(_) => return false,
            },
        };
        expected.ct_eq(tag).into()
    }

    /// Scan a board of fixed-size entries; entry i is at board position `first_index + i`.
    pub fn scan(&self, board: &[u8], first_index: u64) -> Vec<u64> {
        board
            .chunks_exact(self.scheme().entry_len())
            .enumerate()
            .filter_map(|(i, e)| {
                let idx = first_index + i as u64;
                self.check(e, &binding_for_index(idx)).then_some(idx)
            })
            .collect()
    }

    pub fn scan_parallel(&self, board: &[u8], threads: usize) -> Vec<u64>
    where
        Self: Sync,
    {
        let el = self.scheme().entry_len();
        let n = board.len() / el;
        let threads = threads.max(1).min(n.max(1));
        if threads == 1 {
            return self.scan(board, 0);
        }
        let per = n.div_ceil(threads);
        let mut out: Vec<u64> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    let lo = (t * per).min(n);
                    let hi = ((t + 1) * per).min(n);
                    let slice = &board[lo * el..hi * el];
                    sc.spawn(move || self.scan(slice, lo as u64))
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().expect("scan thread panicked")).collect()
        });
        out.sort_unstable();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Scheme; 4] = [Scheme::X25519Dalek, Scheme::X25519AwsLc, Scheme::MlKem512, Scheme::MlKem768];

    fn party(s: Scheme) -> (Receiver, Recipient) {
        let (sk, pk) = keygen(s);
        (Receiver::from_secret(s, &sk), Recipient::from_public(s, &pk))
    }

    #[test]
    fn sizes_match_the_parameter_sets() {
        for s in ALL {
            let (sk, pk) = keygen(s);
            let (want_sk, want_pk) = match s {
                Scheme::X25519Dalek | Scheme::X25519AwsLc => (32, 32),
                Scheme::MlKem512 => (1632, 800),
                Scheme::MlKem768 => (2400, 1184),
            };
            assert_eq!((sk.len(), pk.len()), (want_sk, want_pk), "{}", s.name());
            let (_, to) = party(s);
            assert_eq!(to.make_entry(&binding_for_index(0)).unwrap().len(), s.entry_len());
        }
    }

    #[test]
    fn match_and_non_match() {
        for s in ALL {
            let (rx, to) = party(s);
            let (other, _) = party(s);
            let e = to.make_entry(&binding_for_index(9)).unwrap();
            assert!(rx.check(&e, &binding_for_index(9)), "{} own entry", s.name());
            assert!(!other.check(&e, &binding_for_index(9)), "{} other receiver", s.name());
            assert!(!rx.check(&e, &binding_for_index(10)), "{} moved entry", s.name());
            let mut t = e.clone();
            *t.last_mut().unwrap() ^= 1;
            assert!(!rx.check(&t, &binding_for_index(9)), "{} tampered tag", s.name());
            let mut t = e.clone();
            t[0] ^= 1;
            assert!(!rx.check(&t, &binding_for_index(9)), "{} tampered public value", s.name());
        }
    }

    #[test]
    fn fresh_randomness_per_entry() {
        for s in ALL {
            let (_, to) = party(s);
            let a = to.make_entry(&binding_for_index(1)).unwrap();
            let b = to.make_entry(&binding_for_index(1)).unwrap();
            assert_ne!(a, b, "{}", s.name());
        }
    }

    #[test]
    fn x25519_variants_agree_and_reject_low_order() {
        // Same receiver key in both libraries: entries made by one are accepted by the other.
        let (sk, pk) = keygen(Scheme::X25519Dalek);
        let dalek = Receiver::from_secret(Scheme::X25519Dalek, &sk);
        let aws = Receiver::from_secret(Scheme::X25519AwsLc, &sk);
        let e1 = Recipient::from_public(Scheme::X25519Dalek, &pk).make_entry(&binding_for_index(3)).unwrap();
        let e2 = Recipient::from_public(Scheme::X25519AwsLc, &pk).make_entry(&binding_for_index(3)).unwrap();
        for e in [&e1, &e2] {
            assert!(dalek.check(e, &binding_for_index(3)) && aws.check(e, &binding_for_index(3)));
        }
        let mut low = vec![0u8; 48];
        low[0] = 1; // u = 1 is a low-order point
        assert!(!aws.check(&low, &binding_for_index(0)));
        assert!(Recipient::from_public(Scheme::X25519AwsLc, &[0u8; 32]).make_entry(&binding_for_index(0)).is_none());
    }

    #[test]
    fn random_kem_ciphertext_does_not_match() {
        // Implicit rejection: a ciphertext not made for this key yields a pseudorandom secret.
        for s in [Scheme::MlKem512, Scheme::MlKem768] {
            let (rx, _) = party(s);
            let mut e = vec![0u8; s.entry_len()];
            aws_lc_rs::rand::fill(&mut e).unwrap();
            assert!(!rx.check(&e, &binding_for_index(0)), "{}", s.name());
        }
    }

    #[test]
    fn scan_finds_exactly_the_receivers_entries() {
        for s in ALL {
            let (rx, to) = party(s);
            let others: Vec<Recipient> = (0..4).map(|_| party(s).1).collect();
            let truth = [0u64, 250, 499];
            let mut board = Vec::new();
            for i in 0..500u64 {
                let r = if truth.contains(&i) { &to } else { &others[i as usize % others.len()] };
                board.extend_from_slice(&r.make_entry(&binding_for_index(i)).unwrap());
            }
            assert_eq!(rx.scan(&board, 0), truth.to_vec(), "{}", s.name());
            assert_eq!(rx.scan_parallel(&board, 5), truth.to_vec(), "{} parallel", s.name());
        }
    }
}
