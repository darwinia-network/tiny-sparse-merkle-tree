#![no_std]

extern crate alloc;

// --- alloc ---
use alloc::vec::Vec;

pub type Hash = [u8; 32];

/// ## Tree
/// ```text
/// [1234]
/// [0000,1234]
/// [00,00,12,34]
/// [0,0,0,0,1,2,3,4]
/// ```
///
/// ## Merge steps
/// ```text
/// [0,0,0,0,1,2,3,4]
/// [0,0,0,34,1,2,3,4]
/// [0,0,12,34,1,2,3,4]
/// [0,1234,12,34,1,2,3,4]
/// ```
#[cfg_attr(test, derive(PartialEq))]
pub struct SparseMerkleTree(pub Vec<Hash>);
impl SparseMerkleTree {
	pub fn new<A, T, H>(leaves: A, hashing: H) -> Self
	where
		A: AsRef<[T]>,
		T: AsRef<[u8]>,
		H: Fn(&[u8]) -> Hash,
	{
		let leaves = leaves.as_ref();
		let non_empty_leaves_count = leaves.len() as _;
		let leaves_count = next_pow2(non_empty_leaves_count);
		let size = leaves_count * 2;
		let mut smt = Vec::with_capacity(size as _);

		#[cfg(feature = "debug")]
		{
			log::debug!("{}", non_empty_leaves_count);
			log::debug!("{}", leaves_count);
			log::debug!("{}", size);
		}

		// Fill the empty leaves.
		for _ in 0..leaves_count {
			smt.push([0u8; 32]);
		}
		#[cfg(feature = "debug")]
		log::debug!("{}", &smt.len());
		// Fill the leaves.
		for leaf in leaves.iter() {
			smt.push(hashing(leaf.as_ref()));
		}
		#[cfg(feature = "debug")]
		log::debug!("{}", &smt.len());
		// Fill the empty leaves.
		// `next_pow2(x)` must grater/equal than/to `x`; qed
		for _ in 0..leaves_count - non_empty_leaves_count {
			smt.push([0u8; 32]);
		}
		#[cfg(feature = "debug")]
		log::debug!("{}", &smt.len());

		// Build the SMT.
		for i in (1..leaves_count).map(|i| i as usize).rev() {
			let l = &smt[i * 2];
			let r = &smt[i * 2 + 1];
			let mut m = [0u8; 64];

			m[..32].copy_from_slice(l);
			m[32..].copy_from_slice(r);

			smt[i] = hashing(&m);
		}

		Self(smt)
	}

	pub fn size(&self) -> u32 {
		self.0.len() as _
	}

	pub fn root(&self) -> Hash {
		if self.size() == 0 {
			[0u8; 32]
		} else {
			self.0[1]
		}
	}

	pub fn proof(&self, _indices: Vec<u32>) -> Vec<Hash> {
		todo!()
	}
}

pub fn next_pow2(mut x: u32) -> u32 {
	if x == 0 {
		return 0;
	}

	x -= 1;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	x += 1;

	x
}

#[test]
fn next_pow2_should_work() {
	#[cfg(feature = "debug")]
	let _ = pretty_env_logger::try_init();

	for (&p, x) in [0u32, 1, 2, 4, 4, 8, 8, 8, 8, 16].iter().zip(0u32..) {
		#[cfg(feature = "debug")]
		log::debug!("{}, {}, {}", x, next_pow2(x), p);

		assert_eq!(next_pow2(x), p);
	}
}

#[test]
fn smt_should_work() {
	// --- core ---
	use core::fmt::{Debug, Formatter, Result};
	// --- alloc ---
	use alloc::string::{String, ToString};

	impl Debug for SparseMerkleTree {
		fn fmt(&self, f: &mut Formatter) -> Result {
			f.debug_tuple("SparseMerkleTree")
				.field(&format_args!(
					"{:#?}",
					self.0
						.iter()
						.map(|x| x.iter().map(ToString::to_string).collect::<String>())
						.collect::<Vec<_>>()
				))
				.finish()
		}
	}

	struct Num([u8; 32]);
	impl AsRef<[u8]> for Num {
		fn as_ref(&self) -> &[u8] {
			&self.0
		}
	}
	impl From<u8> for Num {
		fn from(x: u8) -> Self {
			Self([x; 32])
		}
	}

	#[cfg(feature = "debug")]
	let _ = pretty_env_logger::try_init();

	let smt = SparseMerkleTree::new(
		[
			Num::from(1),
			Num::from(2),
			Num::from(3),
			Num::from(4),
			Num::from(5),
		],
		|s| {
			if s.len() == 32 {
				unsafe { *(s.as_ptr() as *const [u8; 32]) }
			} else {
				let mut a = [0; 32];

				for i in 0..s.len() {
					a[i % 32] += s[i];
				}

				a
			}
		},
	);

	#[cfg(feature = "debug")]
	log::debug!("{:?}", smt);

	assert_eq!(smt, {
		let mut smt = SparseMerkleTree(Vec::new());

		for x in [0, 15, 10, 5, 3, 7, 5, 0, 1, 2, 3, 4, 5, 0, 0, 0] {
			smt.0.push([x; 32]);
		}

		smt
	});
}
