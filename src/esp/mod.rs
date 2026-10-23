//! The ESP mint's request and response bodies.

pub mod exchange;
pub mod handover;
pub mod queue;
pub mod redeem;
pub mod rollover;
pub mod terms;
pub mod transfer;

use sha2::Digest;

/// Feed every keyset field of a request into its request hash: the count and
/// each input keyset, then the output keyset, each with its length in front,
/// so no two different lists of keysets hash alike.
pub fn hash_keysets(h: &mut sha2::Sha256, inputs: &[String], output: &str) {
    h.update((inputs.len() as u64).to_be_bytes());
    for k in inputs {
        h.update((k.len() as u64).to_be_bytes());
        h.update(k.as_bytes());
    }
    h.update((output.len() as u64).to_be_bytes());
    h.update(output.as_bytes());
}
