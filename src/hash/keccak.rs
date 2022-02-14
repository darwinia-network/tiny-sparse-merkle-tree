// --- crates.io ---
use tiny_keccak::{Hasher as _, Keccak};
// --- sparse-merkle-tree ---
use crate::{hash::Hasher, *};

pub type Hash = [u8; 32];

pub struct Keccak256;
impl Hasher for Keccak256 {
	type Hash = Hash;

	fn hash<T>(data: T) -> Self::Hash
	where
		T: AsRef<[u8]>,
	{
		let mut keccak = Keccak::v256();
		let mut output = [0u8; 32];

		keccak.update(data.as_ref());
		keccak.finalize(&mut output);

		output
	}
}
impl Merge for Keccak256 {
	type Item = Hash;

	fn merge(l: &Self::Item, r: &Self::Item) -> Self::Item {
		let mut m = [0u8; 64];

		m[..32].copy_from_slice(l.as_ref());
		m[32..].copy_from_slice(r.as_ref());

		Keccak256::hash(&m)
	}
}
