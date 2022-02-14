// --- core ---
use core::fmt::{Debug, Formatter, Result};
// --- sparse-merkle-tree ---
use crate::{
	hash::{Hasher, Keccak256},
	*,
};

#[test]
fn keccak_should_work() {
	impl Debug for SparseMerkleTree<[u8; 32]> {
		fn fmt(&self, f: &mut Formatter) -> Result {
			f.debug_struct("SparseMerkleTree")
				.field(
					"nodes",
					&self
						.nodes
						.iter()
						.map(|node| array_bytes::bytes2hex("0x", node))
						.collect::<Vec<_>>(),
				)
				.finish()
		}
	}

	let _ = pretty_env_logger::try_init();
	let smt = SparseMerkleTree::new::<_, Keccak256>(
		// Secret phrase:       ladder wisdom tenant unique illegal soccer side tobacco flag average help explain
		//   Secret seed:       0xeccfc6d7efea70eec2f6d19acdbb20012732a32268705037bd99c9d27a1bf6e6
		//   Public key (hex):  0x02d3879027ad442b2b56034aab3bb078a09821029e3ac44d9807c1dcd447772ef1
		//   Account ID:        0x9fb19b511826c6a373749976418347cdefef79fce80e07dd2ce01970657d0d1b
		//   Public key (SS58): KW7i17gpPih4y2isWLnAK91cSCLCbqw8AzBmTFUF8mHX3P1j5
		//   SS58 Address:      5Fg6EMUSmmAnnuUKWgLf77AzYXZWcW5SHmrvYsQYk1bM4TWn
		//
		// Secret phrase:       pet lawn antique direct spice produce mother goddess filter car clutch cube
		//   Secret seed:       0xa068c1c894091057772540ae99471613b3d36532baeb6f0999906edd9de34de5
		//   Public key (hex):  0x0315cceb3f6c1eda44a058f5b47733f6187bf0fedcf80bab314f7138109a506b62
		//   Account ID:        0xfbf8f95e0d93479e5cda3eb962cca77f777c95348686b42eb636c87c68a2a3d3
		//   Public key (SS58): KW9CtsxpBKNFfGVBXkkw2j9dVBALbxNqbp1aZWNUH19XCu8eC
		//   SS58 Address:      5Hm5qVqYkZwrumb1ZhsoeQMmJHgfak7fjHXsBuJh9dwEV8Fx
		//
		// Secret phrase:       pulp anxiety hard under ladder embark false nature manual boss artefact range
		//   Secret seed:       0xdee8507f43fbd654d8f1c9e10ed3e5e4c890718d6c1f0b0efbeacdb12109a3ad
		//   Public key (hex):  0x03128f94a05513445c01d7bf0b00dd966f1b55a23445de6ab3e07eb111c02119d9
		//   Account ID:        0xea56729e3baf921beb4e8ab3145152cfc816790e0aa6cc39bc1f2a8e819e1695
		//   Public key (SS58): KW98eWo7AdyFFPCod4BM2iQmuiaXQechHWygv2Epe3BFndjoP
		//   SS58 Address:      5HMxk26G4iQt2PTrrQHkwfVofhh3TgL9wCGXkEo1poQUiiAR
		//
		// Secret phrase:       fresh example grain miracle pumpkin own elephant near laundry elder cliff castle
		//   Secret seed:       0xe87aa93bcc8da23efad86e77c2d051acd2a6af0b073760d9348bfa1be9b63f2d
		//   Public key (hex):  0x02941b426205af1eeba94f4b4a72919878b0dd72d39aa2a41fb1ed2aecd4e8b6fe
		//   Account ID:        0xbcc7634b61918910f4625bca7f6bc84b1434e9322fac3bbee4cf5822cf4da6f3
		//   Public key (SS58): KW6GqvgihGLNeULodbTdDD8BYJ4qcQf6TimQAzwDVoDZrWUqW
		//   SS58 Address:      5GLE6BCFPziNrXForcy1w9wZQS7CkMQHDuu1pEXGN3JMtnZV
		[
			"0x02d3879027ad442b2b56034aab3bb078a09821029e3ac44d9807c1dcd447772ef1",
			"0x0315cceb3f6c1eda44a058f5b47733f6187bf0fedcf80bab314f7138109a506b62",
			"0x03128f94a05513445c01d7bf0b00dd966f1b55a23445de6ab3e07eb111c02119d9",
			"0x02941b426205af1eeba94f4b4a72919878b0dd72d39aa2a41fb1ed2aecd4e8b6fe",
		]
		.iter()
		.map(|hex_pub_key| Keccak256::hash(array_bytes::hex2bytes_unchecked(hex_pub_key))),
	);

	#[cfg(feature = "debug")]
	log::debug!("{:?}", smt);

	[
		[0].as_ref(),
		&[0, 1],
		&[0, 2],
		&[0, 3],
		&[1, 2],
		&[1, 3],
		&[2, 3],
		&[0, 1, 2],
		&[0, 1, 3],
		&[0, 2, 3],
		&[1, 2, 3],
	]
	.iter()
	.for_each(|indices| {
		let mut proof = smt.proof_of(&indices);

		proof.sort();

		assert!(SparseMerkleTree::verify::<Keccak256>(proof));
	});
}
