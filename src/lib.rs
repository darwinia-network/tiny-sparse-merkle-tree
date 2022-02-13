#![no_std]

extern crate alloc;

// --- core ---
use core::{fmt::Debug, marker::PhantomData};
// --- alloc ---
use alloc::vec::Vec;

#[cfg(any(feature = "keccak"))]
pub mod hash {
	#[cfg(feature = "keccak")]
	pub mod keccak {
		// --- crates.io ---
		use tiny_keccak::{Hasher as _, Keccak};
		// --- sparse-merkle-tree ---
		use crate::*;

		pub struct Keccak256;
		impl<'d> Hasher<'d> for Keccak256 {
			type Data = &'d [u8];
			type Hash = [u8; 32];

			fn hash(data: Self::Data) -> Self::Hash {
				let mut keccak = Keccak::v256();
				let mut output = [0u8; 32];

				keccak.update(data);
				keccak.finalize(&mut output);

				output
			}

			fn merge(l: &Self::Hash, r: &Self::Hash) -> Self::Hash {
				let mut m = [0u8; 64];

				m[..32].copy_from_slice(l);
				m[32..].copy_from_slice(r);

				Self::hash(&m)
			}
		}
	}
	#[cfg(feature = "keccak")]
	pub use keccak::*;
}

pub trait Hasher<'d> {
	type Data;
	type Hash;

	fn hash(data: Self::Data) -> Self::Hash;

	fn merge(l: &Self::Hash, r: &Self::Hash) -> Self::Hash;
}

/// > Assume the hash algorithm is `a + b`.
///
/// ## Tree
/// ```text
/// [10]
/// [0,10]
/// [0,0,3,7]
/// [0,0,0,0,1,2,3,4]
/// ```
///
/// ## Merge steps
/// ```text
/// [0,0,0,0,1,2,3,4]
/// [0,0,0,3+4,1,2,3,4]
/// [0,0,1+2,3+4,1,2,3,4]
/// [0,1+2+3+4,1+2,3+4,1,2,3,4]
/// ```
#[cfg_attr(all(feature = "debug", not(test)), derive(Debug))]
pub struct SparseMerkleTree<H, Hs> {
	pub nodes: Vec<H>,
	pub non_empty_leaves_count: u32,
	_phantom_data: PhantomData<Hs>,
}
impl<'d, H, Hs> SparseMerkleTree<H, Hs>
where
	H: Clone + Debug + Default + PartialEq,
	Hs: Hasher<'d, Hash = H>,
{
	pub fn new<T>(leaves: &'d [T]) -> Self
	where
		Hs: Hasher<'d, Data = &'d T>,
	{
		let non_empty_leaves_count = leaves.len() as u32;
		let half_leaves_count = non_empty_to_half_leaves_count(non_empty_leaves_count);
		let leaves_count = half_leaves_count * 2;
		let mut nodes = Vec::with_capacity(leaves_count as _);

		#[cfg(feature = "debug")]
		{
			log::debug!("new::non_empty_leaves_count: {}", non_empty_leaves_count);
			log::debug!("new::half_leaves_count: {}", half_leaves_count);
		}

		// Fill the empty leaves.
		(0..half_leaves_count).for_each(|_| nodes.push(Default::default()));
		// Fill the leaves.
		leaves.iter().for_each(|leaf| nodes.push(Hs::hash(leaf)));
		// Fill the empty leaves.
		// `x.next_power_of_two()` must grater/equal than/to `x`; qed
		(0..half_leaves_count - non_empty_leaves_count)
			.for_each(|_| nodes.push(Default::default()));
		// Build the SMT.
		(1..half_leaves_count).rev().for_each(|i| {
			let i = i as usize;
			let l = &nodes[i * 2];
			let r = &nodes[i * 2 + 1];

			nodes[i] = Hs::merge(l, r);
		});

		Self {
			nodes,
			non_empty_leaves_count,
			_phantom_data: Default::default(),
		}
	}

	pub fn leaves_count(&self) -> u32 {
		self.nodes.len() as _
	}

	#[cfg(test)]
	pub fn half_leaves_count(&self) -> u32 {
		self.leaves_count() / 2
	}

	pub fn non_empty_leaves_count(&self) -> u32 {
		self.non_empty_leaves_count
	}

	pub fn root(&self) -> H {
		if self.leaves_count() == 0 {
			Default::default()
		} else {
			self.nodes[1].clone()
		}
	}

	/// ## Indices
	/// ```text
	// leaves  0 0 0 0 0 0 0 0 1 2 3 4 5 0 0 0
	// indices                 0 1 2 3 4 5 6 7
	/// ```
	pub fn proof_of(&self, indices: &[u32]) -> Proof<H> {
		let leaves_count = self.leaves_count();
		let half_leaves_count = leaves_count / 2;

		if indices.iter().any(|i| *i >= self.non_empty_leaves_count()) {
			log::warn!("proof_of::Index out of bounds.");

			return Default::default();
		}

		let mut known = Vec::with_capacity(leaves_count as _);

		(0..leaves_count).for_each(|_| known.push(false));
		indices
			.iter()
			.for_each(|i| known[(half_leaves_count + *i) as usize] = true);

		let mut proof = Vec::new();

		(1..half_leaves_count).rev().for_each(|i| {
			let i = i as usize;
			let j = i * 2;
			let k = j + 1;
			let l = known[j];
			let r = known[k];

			if l && !r {
				proof.push(self.nodes[k].clone());
			}
			if !l && r {
				proof.push(self.nodes[j].clone());
			}

			known[i] = l || r;
		});

		Proof {
			half_leaves_count,
			root: self.root(),
			leaves_with_index: indices
				.iter()
				.map(|i| {
					let i = half_leaves_count + *i;

					(i, self.nodes[i as usize].clone())
				})
				.collect(),
			proof,
		}
	}

	pub fn verify(proof: Proof<H>) -> bool {
		let Proof {
			half_leaves_count,
			root,
			leaves_with_index: mut nodes_with_indices,
			proof,
		} = proof;

		if nodes_with_indices.is_empty() {
			return false;
		}

		#[cfg(feature = "debug")]
		{
			log::debug!("verify::half_leaves_count: {:?}", half_leaves_count);
			log::debug!("verify::root: {:?}", root);
			log::debug!("verify::nodes_with_indices: {:?}", nodes_with_indices);
			log::debug!("verify::proof: {:?}", proof);
		}

		// Use ptr to avoid extra vector allocation(`remove`).
		let mut p_i = 0;
		let mut n_i = 0;

		while n_i < nodes_with_indices.len() {
			let i = nodes_with_indices[n_i].0;
			// Cache the current `n_i`.
			let n_j = n_i;

			n_i += 1;

			if i == 1 {
				return &root == &nodes_with_indices[n_j].1;
			}
			// Index starts from `0`, left nodes' index is an even number.
			else if i % 2 == 0 {
				if p_i == proof.len() {
					return false;
				}

				nodes_with_indices
					.push((i / 2, Hs::merge(&nodes_with_indices[n_j].1, &proof[p_i])));
				p_i += 1;
			}
			// Check the next node if exists.
			// Notice that the `n_i` was already `+1`.
			else if n_i != nodes_with_indices.len() && nodes_with_indices[n_i].0 == i - 1 {
				nodes_with_indices.push((
					i / 2,
					Hs::merge(&nodes_with_indices[n_j].1, &nodes_with_indices[n_i].1),
				));
				n_i += 1;
			} else {
				if p_i == proof.len() {
					return false;
				}

				nodes_with_indices
					.push((i / 2, Hs::merge(&proof[p_i], &nodes_with_indices[n_j].1)));
				p_i += 1;
			}

			#[cfg(feature = "debug")]
			log::debug!("verify::nodes_with_indices: {:?}", nodes_with_indices);
		}

		false
	}
}

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Default)]
pub struct Proof<H>
where
	H: Default,
{
	half_leaves_count: u32,
	root: H,
	leaves_with_index: Vec<(u32, H)>,
	proof: Vec<H>,
}
impl<H> Proof<H>
where
	H: Clone + Default,
{
	/// Avoid to use this function as far as possible.
	///
	/// Pass the `indices` in descend order to [`SparseMerkleRoot::proof_of`],
	/// then you will get the proof in descend order.
	pub fn sort(&mut self) -> &mut Self {
		self.leaves_with_index.sort_by(|(a, _), (b, _)| b.cmp(a));

		self
	}
}

pub fn non_empty_to_half_leaves_count(non_empty_leaves_count: u32) -> u32 {
	non_empty_leaves_count.next_power_of_two()
}

#[cfg(test)]
mod tests {
	// --- core ---
	use core::fmt::{Debug, Formatter, Result};
	// --- sparse-merkle-tree ---
	use crate::*;

	type TestSparseMerkleTrie = SparseMerkleTree<u32, ()>;

	impl<'d> Hasher<'d> for () {
		type Data = &'d u32;
		type Hash = u32;

		fn hash(data: Self::Data) -> Self::Hash {
			*data
		}

		fn merge(l: &Self::Hash, r: &Self::Hash) -> Self::Hash {
			*l + *r
		}
	}

	impl TestSparseMerkleTrie {
		fn new_with_leaves_count(half_leaves_count: u32) -> Self {
			let mut leaves = Vec::new();

			(1..=half_leaves_count).for_each(|i| leaves.push(i));

			TestSparseMerkleTrie::new(&leaves)
		}
	}
	impl Debug for TestSparseMerkleTrie {
		fn fmt(&self, f: &mut Formatter) -> Result {
			f.debug_struct("TestSparseMerkleTrie")
				.field("nodes", &self.nodes)
				.finish()
		}
	}

	struct TestProof {
		smt: TestSparseMerkleTrie,
		indices: Vec<u32>,
		proof: Vec<u32>,
	}
	impl TestProof {
		fn of_smt(smt: TestSparseMerkleTrie) -> Self {
			Self {
				smt,
				indices: Vec::new(),
				proof: Vec::new(),
			}
		}

		fn of_indices(&mut self, indices: &[u32]) -> &mut Self {
			self.indices = indices.to_vec();
			self.proof = self.smt.proof_of(&self.indices).proof;

			self
		}
	}
	impl Debug for TestProof {
		fn fmt(&self, f: &mut Formatter) -> Result {
			f.debug_struct("TestProof")
				.field("smt", &self.smt)
				.field(
					"leaves",
					&format_args!("{:?}", {
						let half_leaves_count = self.smt.half_leaves_count();

						self.indices
							.iter()
							.map(|i| self.smt.nodes[(half_leaves_count + *i) as usize])
							.collect::<Vec<_>>()
					}),
				)
				.field("proof", &format_args!("{:?}", &self.proof))
				.finish()
		}
	}

	#[test]
	fn smt_should_work() {
		let _ = pretty_env_logger::try_init();
		//                15
		//        0               15
		//    0       0       10      5
		//  0   0   0   0   3   7   5   0
		// 0 0 0 0 0 0 0 0 1 2 3 4 5 0 0 0
		let smt = TestSparseMerkleTrie::new_with_leaves_count(5);

		#[cfg(feature = "debug")]
		log::debug!("{:?}", smt);

		assert_eq!(smt.nodes, {
			let mut nodes = Vec::new();

			[0, 15, 10, 5, 3, 7, 5, 0, 1, 2, 3, 4, 5, 0, 0, 0]
				.iter()
				.for_each(|x| nodes.push(*x));

			nodes
		});
	}

	#[test]
	fn proof_should_work() {
		let _ = pretty_env_logger::try_init();
		//                10
		//            0       10
		//          0   0   3   7
		// leaves  0 0 0 0 1 2 3 4
		// indices         0 1 2 3
		let mut debug_proof = TestProof::of_smt(TestSparseMerkleTrie::new_with_leaves_count(4));

		[
			([0].as_ref(), [2, 7].as_ref()),
			(&[0, 1], &[7]),
			(&[0, 2], &[4, 2]),
			(&[0, 3], &[3, 2]),
			(&[1, 2], &[4, 1]),
			(&[1, 3], &[3, 1]),
			(&[2, 3], &[3]),
			(&[0, 1, 2], &[4]),
			(&[0, 1, 3], &[3]),
			(&[0, 2, 3], &[2]),
			(&[1, 2, 3], &[1]),
		]
		.iter()
		.for_each(|(indices, proof)| {
			debug_proof.of_indices(indices);

			#[cfg(feature = "debug")]
			log::debug!("{:?}", debug_proof);

			assert_eq!(&debug_proof.proof, proof);
		});

		//                        15
		//                0               15
		//            0       0       10      5
		//          0   0   0   0   3   7   5   0
		// leaves  0 0 0 0 0 0 0 0 1 2 3 4 5 0 0 0
		// indices                 0 1 2 3 4 5 6 7
		let mut debug_proof = TestProof::of_smt(TestSparseMerkleTrie::new_with_leaves_count(5));

		[
			([0].as_ref(), [2, 7, 5].as_ref()),
			(&[0, 1], &[7, 5]),
			(&[0, 2], &[4, 2, 5]),
			(&[0, 3], &[3, 2, 5]),
			(&[0, 4], &[0, 2, 0, 7]),
			(&[1, 2], &[4, 1, 5]),
			(&[1, 3], &[3, 1, 5]),
			(&[1, 4], &[0, 1, 0, 7]),
			(&[2, 3], &[3, 5]),
			(&[2, 4], &[0, 4, 0, 3]),
			(&[3, 4], &[0, 3, 0, 3]),
			(&[0, 1, 2], &[4, 5]),
			(&[0, 1, 3], &[3, 5]),
			(&[0, 1, 4], &[0, 0, 7]),
			(&[0, 2, 3], &[2, 5]),
			(&[0, 2, 4], &[0, 4, 2, 0]),
			(&[0, 3, 4], &[0, 3, 2, 0]),
			(&[1, 2, 3], &[1, 5]),
			(&[1, 2, 4], &[0, 4, 1, 0]),
			(&[2, 3, 4], &[0, 0, 3]),
			(&[0, 1, 2, 3], &[5]),
			(&[0, 1, 2, 4], &[0, 4, 0]),
			(&[0, 2, 3, 4], &[0, 2, 0]),
			(&[0, 1, 2, 3, 4], &[0, 0]),
		]
		.iter()
		.for_each(|(indices, proof)| {
			debug_proof.of_indices(indices);

			#[cfg(feature = "debug")]
			log::debug!("{:?}", debug_proof);

			assert_eq!(&debug_proof.proof, proof);
		});
	}

	#[test]
	fn verify_should_work() {
		let _ = pretty_env_logger::try_init();
		//                             15
		//                     0               15
		//                 0       0       10      5
		//               0   0   0   0   3   7   5   0
		// leaves       0 0 0 0 0 0 0 0 1 2 3 4 5 0 0 0
		// indices                      0 1 2 3 4 5 6 7
		// node indices 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
		let smt = TestSparseMerkleTrie::new_with_leaves_count(5);

		[
			[0].as_ref(),
			&[0, 1],
			&[0, 2],
			&[0, 3],
			&[0, 4],
			&[1, 2],
			&[1, 3],
			&[1, 4],
			&[2, 3],
			&[2, 4],
			&[3, 4],
			&[0, 1, 2],
			&[0, 1, 3],
			&[0, 1, 4],
			&[0, 2, 3],
			&[0, 2, 4],
			&[0, 3, 4],
			&[1, 2, 3],
			&[1, 2, 4],
			&[2, 3, 4],
			&[0, 1, 2, 3],
			&[0, 1, 2, 4],
			&[0, 2, 3, 4],
			&[0, 1, 2, 3, 4],
		]
		.iter()
		.for_each(|indices| {
			let mut proof = smt.proof_of(indices);
			let mut indices = indices.to_vec();

			proof.sort();
			indices.sort_by(|a, b| b.cmp(a));

			assert!(TestSparseMerkleTrie::verify(proof));
			assert!(TestSparseMerkleTrie::verify(smt.proof_of(&indices)));
		});
	}
}
