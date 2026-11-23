use crate::protocol::{post_bytes, read_chunk, read_u32_le, wrap_chunk};
use std::error::Error;

pub fn init_deaddrop(base: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let resp = post_bytes(base, "/init", b"")?;
    let mut off = 0;
    let sk_decode = read_chunk(&resp, &mut off)?;
    let pk_clue = read_chunk(&resp, &mut off)?;
    let pk_detect = read_chunk(&resp, &mut off)?;
    if off != resp.len() {
        return Err("extra bytes after /init".into());
    }
    Ok((sk_decode, pk_clue, pk_detect))
}

pub fn gen_clue(base: &str, pk_clue: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = Vec::with_capacity(4 + pk_clue.len());
    body.extend_from_slice(&wrap_chunk(pk_clue));
    let resp = post_bytes(base, "/gen_clue", &body)?;
    let mut off = 0;
    let clue = read_chunk(&resp, &mut off)?;
    if off != resp.len() {
        return Err("extra bytes after /gen_clue payload".into());
    }
    Ok(clue)
}

pub fn submit_clue(base: &str, clue: &[u8], index: i32) -> Result<(), Box<dyn Error>> {
    let mut body = Vec::with_capacity(8 + clue.len());
    body.extend_from_slice(&wrap_chunk(clue));
    body.extend_from_slice(&wrap_chunk(&index.to_le_bytes()));
    let resp = post_bytes(base, "/submit_clue", &body)?;
    let response_text = String::from_utf8(resp)?;
    if response_text == "OK" {
        Ok(())
    } else {
        Err(format!("Submit failed: {response_text}").into())
    }
}

pub fn gen_encrypted_digest(base: &str, pk_detect: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = Vec::with_capacity(4 + pk_detect.len());
    body.extend_from_slice(&wrap_chunk(pk_detect));
    let resp = post_bytes(base, "/gen_encrypted_digest", &body)?;
    let mut off = 0;
    let digest = read_chunk(&resp, &mut off)?;
    if off != resp.len() {
        return Err("extra bytes after digest".into());
    }
    Ok(digest)
}

pub fn decode_digest(
    base: &str,
    digest: &[u8],
    sk_decode: &[u8],
) -> Result<Vec<u64>, Box<dyn Error>> {
    let mut body = Vec::with_capacity(8 + digest.len() + sk_decode.len());
    body.extend_from_slice(&wrap_chunk(digest));
    body.extend_from_slice(&wrap_chunk(sk_decode));
    let resp = post_bytes(base, "/decode_digest", &body)?;
    let mut off = 0;
    let n = read_u32_le(&resp, &mut off)? as usize;
    if resp.len() != 4 + n * 8 {
        return Err("decoded length mismatch".into());
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let b = &resp[4 + i * 8..4 + (i + 1) * 8];
        let mut word = [0u8; 8];
        word.copy_from_slice(b);
        out.push(u64::from_le_bytes(word));
    }
    Ok(out)
}

/// Number of message blocks one digest slot can hold. The detector multiplies block `b` by `2^b`
/// before summing mod t = 65537, and 2^16 = -1 mod t, so only bits 0..=15 are unambiguous.
pub const MAX_DIGEST_BLOCKS: u32 = 16;

/// Turns a decoded digest into the sorted list of pertinent message indices.
///
/// The detector packs the pertinency vector block by block: slot `s` holds
/// `sum_b 2^b * PV[b * D + s] mod t`, where `D = digest.len()` is the number of slots in one
/// ciphertext. Bit `b` of slot `s` therefore flags message `b * D + s`. A slot value of 2^16 or
/// more means the digest covers more than `MAX_DIGEST_BLOCKS` blocks or is corrupted, and the
/// indices cannot be recovered from it.
pub fn digest_to_indices(digest: &[u64]) -> Result<Vec<u64>, Box<dyn Error>> {
    let slots = digest.len() as u64;
    let mut indices = Vec::new();
    for (slot, &value) in digest.iter().enumerate() {
        if value >> MAX_DIGEST_BLOCKS != 0 {
            return Err(format!(
                "digest slot {slot} holds {value}, which is not a valid bitmask of at most \
                 {MAX_DIGEST_BLOCKS} blocks"
            )
            .into());
        }
        for block in 0..MAX_DIGEST_BLOCKS as u64 {
            if (value >> block) & 1 == 1 {
                indices.push(block * slots + slot as u64);
            }
        }
    }
    indices.sort_unstable();
    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOTS: usize = 32768;
    const T: u64 = 65537;

    /// Mirrors the detector's compression step: block b is scaled by 2^b and summed mod t.
    fn pack(pertinent: &[u64], num_messages: usize) -> Vec<u64> {
        let mut digest = vec![0u64; SLOTS];
        for &index in pertinent {
            assert!((index as usize) < num_messages);
            let (block, slot) = (index as usize / SLOTS, index as usize % SLOTS);
            digest[slot] = (digest[slot] + (1u64 << block) % T) % T;
        }
        digest
    }

    #[test]
    fn empty_digest_has_no_indices() {
        assert!(digest_to_indices(&pack(&[], SLOTS)).unwrap().is_empty());
    }

    #[test]
    fn single_block_matches_slot_positions() {
        let pertinent = vec![0, 500, 1000, 1234, 6969, 32767];
        assert_eq!(digest_to_indices(&pack(&pertinent, SLOTS)).unwrap(), pertinent);
    }

    #[test]
    fn indices_beyond_the_first_block_are_recovered() {
        // 131,072 and 524,288 messages are 4 and 16 blocks.
        let pertinent = vec![7, 32768, 40000, 65536 + 7, 131071];
        assert_eq!(digest_to_indices(&pack(&pertinent, 131072)).unwrap(), pertinent);

        let pertinent = vec![5, 32768 + 5, 300000, 15 * 32768, 524287];
        assert_eq!(digest_to_indices(&pack(&pertinent, 524288)).unwrap(), pertinent);
    }

    #[test]
    fn reports_sharing_a_slot_are_all_recovered() {
        let pertinent: Vec<u64> = (0..16).map(|block| block * SLOTS as u64 + 42).collect();
        let digest = pack(&pertinent, 524288);
        assert_eq!(digest[42], 0xFFFF);
        assert_eq!(digest_to_indices(&digest).unwrap(), pertinent);
    }

    #[test]
    fn pseudo_random_sets_round_trip_at_every_size() {
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for blocks in [1usize, 4, 16] {
            let num_messages = blocks * SLOTS;
            for _ in 0..200 {
                let mut pertinent: Vec<u64> =
                    (0..50).map(|_| next() % num_messages as u64).collect();
                pertinent.sort_unstable();
                pertinent.dedup();
                assert_eq!(
                    digest_to_indices(&pack(&pertinent, num_messages)).unwrap(),
                    pertinent
                );
            }
        }
    }

    #[test]
    fn seventeenth_block_is_rejected_or_lost() {
        // 2^16 = -1 mod t: a lone report in block 16 decodes to 65536, which is rejected.
        let digest = pack(&[16 * SLOTS as u64 + 5], 17 * SLOTS);
        assert_eq!(digest[5], 65536);
        assert!(digest_to_indices(&digest).is_err());
    }
}
