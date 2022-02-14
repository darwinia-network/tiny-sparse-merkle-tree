// --- sparse-merkle-tree ---
use crate::*;

/// Easy for debugging the tree state.
pub struct DebugView;
impl Merge for DebugView {
	type Item = u32;

	fn merge(l: &Self::Item, r: &Self::Item) -> Self::Item {
		*l + *r
	}
}

/// Require the merge order to be the same as which we used in the build.
pub struct CheckMergeOrder;
impl Merge for CheckMergeOrder {
	type Item = u32;

	fn merge(l: &Self::Item, r: &Self::Item) -> Self::Item {
		2 * *l + *r
	}
}
