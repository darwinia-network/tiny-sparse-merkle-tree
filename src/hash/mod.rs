pub trait Hasher {
	type Hash;

	fn hash<T>(data: T) -> Self::Hash
	where
		T: AsRef<[u8]>;
}

#[cfg(feature = "keccak")]
pub mod keccak;
#[cfg(feature = "keccak")]
pub use keccak::*;

#[cfg(test)]
pub mod test;
#[cfg(test)]
pub use test::*;
