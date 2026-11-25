//! Recipient-private Local Tag Scan baseline for experiment E2.
//!
//! Each board entry carries `E || tag` (48 bytes):
//!
//! * `E` is a fresh ephemeral X25519 public key chosen by the sender for this entry.
//! * `ss = X25519(esk, PK_R)`, `K = HKDF-SHA256(ikm = ss, salt = E, info = "DeadDrop-TagScan-v1")`.
//! * `tag = first 16 bytes of HMAC-SHA256(K, "match" || E || entry_binding)`.
//!
//! `entry_binding` is the entry's absolute board position as a little-endian u64. Both parties
//! know it without extra bytes: the sender fixes the position when it submits (as the prototype's
//! `submit_clue(clue, index)` does) and the receiver knows the position of each entry in the list
//! it downloads. No receiver identifier or publicly testable recipient hash appears in the entry.
//!
//! The receiver scans an entry by recomputing `ss' = X25519(SK_R, E)`, deriving `K` and comparing
//! the tag in constant time. Non-contributory (all-zero) shared secrets, which arise from
//! low-order points, are rejected on both sides.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

pub const INFO: &[u8] = b"DeadDrop-TagScan-v1";
pub const MATCH_LABEL: &[u8] = b"match";
pub const EPK_BYTES: usize = 32;
pub const TAG_BYTES: usize = 16;
pub const ENTRY_BYTES: usize = EPK_BYTES + TAG_BYTES;

pub type Entry = [u8; ENTRY_BYTES];

#[derive(Debug, PartialEq, Eq)]
pub enum TagError {
    /// The receiver public key is a low-order point: the shared secret would be all zero.
    NonContributory,
}

/// The public binding for the entry at absolute board position `index`.
pub fn binding_for_index(index: u64) -> [u8; 8] {
    index.to_le_bytes()
}

/// The tag derivation shared by every scheme: `K = HKDF-SHA256(ikm = ss, salt = public, info)`,
/// `tag = HMAC-SHA256(K, "match" || public || binding)[..16]`, where `public` is the per-entry
/// public value (the ephemeral X25519 key, or the ML-KEM ciphertext).
pub fn tag_from_secret(ss: &[u8], public: &[u8], binding: &[u8], info: &[u8]) -> [u8; TAG_BYTES] {
    let hk = Hkdf::<Sha256>::new(Some(public), ss);
    let mut k = [0u8; 32];
    hk.expand(info, &mut k).expect("32 bytes is a valid HKDF-SHA256 output length");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&k).expect("HMAC accepts any key length");
    mac.update(MATCH_LABEL);
    mac.update(public);
    mac.update(binding);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&full[..TAG_BYTES]);
    tag
}

fn derive_tag(ss: &SharedSecret, epk: &[u8; EPK_BYTES], binding: &[u8]) -> [u8; TAG_BYTES] {
    tag_from_secret(ss.as_bytes(), epk, binding, INFO)
}

pub mod schemes;

/// Sender side: build the detection metadata for one entry addressed to `pk_r`.
/// A fresh ephemeral key is drawn from the OS RNG for every call.
pub fn make_entry(pk_r: &PublicKey, binding: &[u8]) -> Result<Entry, TagError> {
    let esk = EphemeralSecret::random();
    let epk = PublicKey::from(&esk);
    let ss = esk.diffie_hellman(pk_r);
    if !ss.was_contributory() {
        return Err(TagError::NonContributory);
    }
    let tag = derive_tag(&ss, epk.as_bytes(), binding);
    let mut entry = [0u8; ENTRY_BYTES];
    entry[..EPK_BYTES].copy_from_slice(epk.as_bytes());
    entry[EPK_BYTES..].copy_from_slice(&tag);
    Ok(entry)
}

/// Receiver side: does this entry belong to the holder of `sk_r`?
/// Runs one X25519, one HKDF and one HMAC, then compares tags in constant time.
pub fn check_entry(sk_r: &StaticSecret, entry: &[u8], binding: &[u8]) -> bool {
    if entry.len() != ENTRY_BYTES {
        return false;
    }
    let mut epk = [0u8; EPK_BYTES];
    epk.copy_from_slice(&entry[..EPK_BYTES]);
    let ss = sk_r.diffie_hellman(&PublicKey::from(epk));
    // Evaluate the tag even for non-contributory points so the work per entry is uniform.
    let contributory = ss.was_contributory();
    let tag = derive_tag(&ss, &epk, binding);
    let tag_ok: bool = tag.ct_eq(&entry[EPK_BYTES..]).into();
    contributory && tag_ok
}

/// Receiver side: scan `board` (concatenated 48-byte entries, entry `i` at board position
/// `first_index + i`) and return the absolute positions of matching entries.
pub fn scan(sk_r: &StaticSecret, board: &[u8], first_index: u64) -> Vec<u64> {
    board
        .chunks_exact(ENTRY_BYTES)
        .enumerate()
        .filter_map(|(i, e)| {
            let idx = first_index + i as u64;
            if check_entry(sk_r, e, &binding_for_index(idx)) {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

/// Same as `scan`, split across `threads` OS threads.
pub fn scan_parallel(sk_r: &StaticSecret, board: &[u8], threads: usize) -> Vec<u64> {
    let n = board.len() / ENTRY_BYTES;
    let threads = threads.max(1).min(n.max(1));
    if threads == 1 {
        return scan(sk_r, board, 0);
    }
    let per = n.div_ceil(threads);
    let mut out: Vec<u64> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let lo = (t * per).min(n);
                let hi = ((t + 1) * per).min(n);
                let slice = &board[lo * ENTRY_BYTES..hi * ENTRY_BYTES];
                s.spawn(move || scan(sk_r, slice, lo as u64))
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().expect("scan thread panicked")).collect()
    });
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receiver() -> (StaticSecret, PublicKey) {
        let sk = StaticSecret::random();
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    #[test]
    fn entry_is_48_bytes_and_matches_its_receiver() {
        let (sk, pk) = receiver();
        let e = make_entry(&pk, &binding_for_index(7)).unwrap();
        assert_eq!(e.len(), 48);
        assert!(check_entry(&sk, &e, &binding_for_index(7)));
    }

    #[test]
    fn other_receiver_does_not_match() {
        let (_, pk) = receiver();
        let (sk_other, _) = receiver();
        let e = make_entry(&pk, &binding_for_index(7)).unwrap();
        assert!(!check_entry(&sk_other, &e, &binding_for_index(7)));
    }

    #[test]
    fn moved_entry_does_not_match() {
        let (sk, pk) = receiver();
        let e = make_entry(&pk, &binding_for_index(7)).unwrap();
        assert!(!check_entry(&sk, &e, &binding_for_index(8)));
    }

    #[test]
    fn tampered_tag_or_key_does_not_match() {
        let (sk, pk) = receiver();
        let mut e = make_entry(&pk, &binding_for_index(3)).unwrap();
        e[47] ^= 1;
        assert!(!check_entry(&sk, &e, &binding_for_index(3)));
        let mut e = make_entry(&pk, &binding_for_index(3)).unwrap();
        e[0] ^= 1;
        assert!(!check_entry(&sk, &e, &binding_for_index(3)));
    }

    #[test]
    fn fresh_ephemeral_key_per_entry() {
        let (_, pk) = receiver();
        let a = make_entry(&pk, &binding_for_index(1)).unwrap();
        let b = make_entry(&pk, &binding_for_index(1)).unwrap();
        assert_ne!(a[..32], b[..32]);
        assert_ne!(a[32..], b[32..]);
    }

    #[test]
    fn low_order_points_are_rejected() {
        let (sk, _) = receiver();
        // u = 0 and u = 1 are low-order points on Curve25519.
        for u in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            // Receiver side: an entry whose E is low order never matches, even with the
            // tag an attacker can compute from the all-zero shared secret.
            let zero_ss_tag = {
                let ss = sk.diffie_hellman(&PublicKey::from(u));
                assert!(!ss.was_contributory());
                derive_tag(&ss, &u, &binding_for_index(0))
            };
            let mut e = [0u8; ENTRY_BYTES];
            e[..32].copy_from_slice(&u);
            e[32..].copy_from_slice(&zero_ss_tag);
            assert!(!check_entry(&sk, &e, &binding_for_index(0)));
            // Sender side: refuses a low-order receiver key.
            assert_eq!(make_entry(&PublicKey::from(u), &binding_for_index(0)), Err(TagError::NonContributory));
        }
    }

    #[test]
    fn scan_finds_exactly_the_receivers_entries() {
        let (sk, pk) = receiver();
        let others: Vec<PublicKey> = (0..8).map(|_| receiver().1).collect();
        let n = 1000u64;
        let truth = [0u64, 499, 999];
        let mut board = Vec::with_capacity(n as usize * ENTRY_BYTES);
        for i in 0..n {
            let to = if truth.contains(&i) { &pk } else { &others[i as usize % others.len()] };
            board.extend_from_slice(&make_entry(to, &binding_for_index(i)).unwrap());
        }
        assert_eq!(scan(&sk, &board, 0), truth.to_vec());
        assert_eq!(scan_parallel(&sk, &board, 7), truth.to_vec());
    }
}
