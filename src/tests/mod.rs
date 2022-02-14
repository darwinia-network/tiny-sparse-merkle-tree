#[cfg(feature = "keccak")]
mod keccak;

// --- core ---
use core::fmt::{Debug, Formatter, Result};
// --- sparse-merkle-tree ---
use crate::{hash::test::*, *};

type TestSparseMerkleTrie = SparseMerkleTree<u32>;

impl TestSparseMerkleTrie {
	fn new_with_leaves_count<T>(half_leaves_count: u32) -> Self
	where
		T: Merge<Item = u32>,
	{
		let mut leaves = Vec::new();

		(1..=half_leaves_count).for_each(|i| leaves.push(i));

		TestSparseMerkleTrie::new::<_, T>(leaves.into_iter())
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
	let smt = TestSparseMerkleTrie::new_with_leaves_count::<DebugView>(5);

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
	let mut debug_proof =
		TestProof::of_smt(TestSparseMerkleTrie::new_with_leaves_count::<DebugView>(4));

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
	let mut debug_proof =
		TestProof::of_smt(TestSparseMerkleTrie::new_with_leaves_count::<DebugView>(5));

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
	let indices_set = [
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
	];

	//                             15
	//                     0               15
	//                 0       0       10      5
	//               0   0   0   0   3   7   5   0
	// leaves       0 0 0 0 0 0 0 0 1 2 3 4 5 0 0 0
	// indices                      0 1 2 3 4 5 6 7
	// node indices 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
	let smt = TestSparseMerkleTrie::new_with_leaves_count::<DebugView>(5);

	indices_set.iter().for_each(|indices| {
		let mut proof = smt.proof_of(indices);
		let mut indices = indices.to_vec();

		proof.sort();
		indices.sort_by(|a, b| b.cmp(a));

		assert!(TestSparseMerkleTrie::verify::<DebugView>(proof));
		assert!(TestSparseMerkleTrie::verify::<DebugView>(
			smt.proof_of(&indices)
		));
	});

	let smt = TestSparseMerkleTrie::new_with_leaves_count::<CheckMergeOrder>(5);

	indices_set.iter().for_each(|indices| {
		let mut proof = smt.proof_of(indices);

		proof.sort();

		assert!(TestSparseMerkleTrie::verify::<CheckMergeOrder>(proof));
	});
}
