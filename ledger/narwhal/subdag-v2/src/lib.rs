// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![forbid(unsafe_code)]
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_console as console;

mod bytes;
mod serialize;
mod string;

use console::{account::Address, prelude::*, program::SUBDAG_CERTIFICATES_DEPTH, types::Field};
use snarkvm_ledger_committee::Committee;
use snarkvm_ledger_narwhal_batch_v2::BatchV2;
use snarkvm_ledger_narwhal_transmission_id::TransmissionID;

use indexmap::IndexSet;
use std::collections::BTreeMap;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// The number of rounds in a Mysticeti commit window: leader round r, support round r+1, commit round r+2.
const COMMIT_WINDOW: usize = 3;

/// Returns `true` if the rounds are sequential.
fn is_sequential<T>(map: &BTreeMap<u64, T>) -> bool {
    let mut previous_round = None;
    for &round in map.keys() {
        match previous_round {
            Some(previous) if previous + 1 != round => return false,
            _ => previous_round = Some(round),
        }
    }
    true
}

/// Checks that the given subDAG is not partitioned and batches are ordered as expected, by
/// traversing it starting from the commit round (r+2) back to the leader at round r.
///
/// Returns `true` if the DFS traversal from the commit round reaches the leader batch.
/// Note: this does not guarantee the subDAG contains all batches it should, as this function
/// has no knowledge of other blocks/subdags.
fn sanity_check_subdag_with_dfs<N: Network>(subdag: &BTreeMap<u64, IndexSet<BatchV2<N>>>) -> bool {
    use std::collections::HashSet;

    // Initialize a map for the batches to commit.
    let mut commit = BTreeMap::<u64, IndexSet<_>>::new();
    // Initialize a set for the already ordered batch IDs.
    let mut already_ordered = HashSet::new();
    // Initialize a buffer for the batches to order, starting from the commit round (last round).
    let mut buffer = subdag.iter().next_back().map_or(Default::default(), |(_, batches)| batches.clone());
    // Traverse the DAG backwards from the commit round.
    while let Some(batch) = buffer.pop() {
        // Insert the batch into the commit map.
        commit.entry(batch.round()).or_default().insert(batch.clone());
        // Follow the previous batch IDs to the prior round.
        for previous_batch_id in batch.previous_batch_ids() {
            let Some(previous_batch) = subdag
                .get(&(batch.round() - 1))
                .and_then(|map| map.iter().find(|b| b.batch_id() == *previous_batch_id))
            else {
                // Either already ordered or below the GC round.
                continue;
            };
            // Skip if already visited.
            if !already_ordered.insert(previous_batch.batch_id()) {
                continue;
            }
            // Add to the buffer.
            buffer.insert(previous_batch.clone());
        }
    }
    // Return `true` if the traversal reconstructs the subdag exactly.
    &commit == subdag
}

/// Returns the weighted median timestamp of the given timestamps and stakes.
fn weighted_median(timestamps_and_stake: Vec<(i64, u64)>) -> i64 {
    let mut timestamps_and_stake = timestamps_and_stake;

    // Sort the timestamps.
    #[cfg(not(feature = "serial"))]
    timestamps_and_stake.par_sort_unstable_by_key(|(timestamp, _)| *timestamp);
    #[cfg(feature = "serial")]
    timestamps_and_stake.sort_unstable_by_key(|(timestamp, _)| *timestamp);

    // Calculate the total stake of the authors.
    let total_stake = timestamps_and_stake.iter().map(|(_, stake)| *stake).sum::<u64>();

    // Initialize the current timestamp and accumulated stake.
    let mut current_timestamp: i64 = 0;
    let mut accumulated_stake: u64 = 0;

    // Find the weighted median timestamp.
    for (timestamp, stake) in timestamps_and_stake.iter() {
        accumulated_stake = accumulated_stake.saturating_add(*stake);
        current_timestamp = *timestamp;
        if accumulated_stake.saturating_mul(2) >= total_stake {
            break;
        }
    }

    current_timestamp
}

/// A Mysticeti commit subdag spanning exactly three rounds: the leader round r, the support
/// round r+1, and the commit round r+2.
///
/// Unlike the Narwhal `Subdag`, quorum approval is not embedded in individual batches.
/// Instead, it is proven structurally: the commit round must contain batches from validators
/// with combined stake ≥ 2f+1 that transitively reference the leader. This stake check is
/// performed at the block-verification level, not here.
#[derive(Clone)]
pub struct SubdagV2<N: Network> {
    /// The subdag of round batches.
    subdag: BTreeMap<u64, IndexSet<BatchV2<N>>>,
}

impl<N: Network> PartialEq for SubdagV2<N> {
    fn eq(&self, other: &Self) -> bool {
        self.subdag == other.subdag
    }
}

impl<N: Network> Eq for SubdagV2<N> {}

impl<N: Network> SubdagV2<N> {
    /// Initializes a new subdag, validating its structure.
    pub fn from(subdag: BTreeMap<u64, IndexSet<BatchV2<N>>>) -> Result<Self> {
        // Ensure the subdag is not empty.
        ensure!(!subdag.is_empty(), "SubdagV2 cannot be empty");
        // Ensure the subdag spans exactly the three-round commit window.
        ensure!(
            subdag.len() == COMMIT_WINDOW,
            "SubdagV2 must span exactly {COMMIT_WINDOW} rounds, got {}",
            subdag.len()
        );
        // Ensure the rounds are sequential.
        ensure!(is_sequential(&subdag), "SubdagV2 rounds must be sequential");
        // Ensure there is exactly one leader batch in the first (leader) round.
        ensure!(
            subdag.iter().next().map_or(0, |(_, b)| b.len()) == 1,
            "SubdagV2 leader round must contain exactly one batch"
        );
        // Ensure the support round (r+1) and commit round (r+2) are non-empty.
        ensure!(
            subdag.iter().nth(1).map_or(0, |(_, b)| b.len()) >= 1,
            "SubdagV2 support round must contain at least one batch"
        );
        ensure!(
            subdag.iter().next_back().map_or(0, |(_, b)| b.len()) >= 1,
            "SubdagV2 commit round must contain at least one batch"
        );
        // Ensure the subdag structure matches the DFS traversal from the commit round.
        ensure!(sanity_check_subdag_with_dfs(&subdag), "SubdagV2 structure does not match commit");
        Ok(Self { subdag })
    }

    /// Initializes a new subdag without checking it for correctness/consistency.
    pub fn from_unchecked(subdag: BTreeMap<u64, IndexSet<BatchV2<N>>>) -> Self {
        Self { subdag }
    }
}

impl<N: Network> SubdagV2<N> {
    /// The maximum number of rounds stored before garbage collecting.
    pub const MAX_ROUNDS: u64 = BatchV2::<N>::MAX_GC_ROUNDS as u64;
}

impl<N: Network> SubdagV2<N> {
    /// Returns the leader round (the first round in the commit window).
    pub fn leader_round(&self) -> u64 {
        self.subdag.iter().next().map_or(0, |(round, _)| *round)
    }

    /// Returns the commit round (the last round in the commit window, leader round + 2).
    pub fn commit_round(&self) -> u64 {
        self.subdag.iter().next_back().map_or(0, |(round, _)| *round)
    }

    /// Returns the batch IDs of the subdag (from earliest round to latest round).
    pub fn batch_ids(&self) -> impl Iterator<Item = Field<N>> + '_ {
        self.values().flatten().map(BatchV2::batch_id)
    }

    /// Returns the batches in this subdag (from earliest round to latest round).
    pub fn batches(&self) -> impl Iterator<Item = &BatchV2<N>> {
        self.values().flatten()
    }

    /// Returns the leader batch (the single batch in the leader round).
    pub fn leader_batch(&self) -> &BatchV2<N> {
        let entry = self.subdag.iter().next();
        debug_assert!(entry.is_some(), "There must be at least one round of batches");
        let batches = entry.expect("There must be one round in the subdag").1;
        debug_assert!(batches.len() == 1, "There must be only one leader batch, by definition");
        // Safe: validated in `from` that the leader round contains exactly one batch.
        batches.iter().next().expect("There must be a leader batch")
    }

    /// Returns the address of the leader.
    pub fn leader_address(&self) -> Address<N> {
        self.leader_batch().author()
    }

    /// Returns the transmission IDs of the subdag (from earliest round to latest round).
    pub fn transmission_ids(&self) -> impl Iterator<Item = &TransmissionID<N>> {
        self.values().flatten().flat_map(BatchV2::transmission_ids)
    }

    /// Returns the timestamp, defined as the weighted median timestamp of the support round (r+1).
    pub fn timestamp(&self, committee: &Committee<N>) -> i64 {
        // Retrieve the support round (leader round + 1).
        let support_round = self.leader_round().saturating_add(1);
        // Retrieve the timestamps and stakes of batches in the support round.
        let timestamps_and_stakes = self
            .values()
            .flatten()
            .filter(|batch| batch.round() == support_round)
            .map(|batch| (batch.timestamp(), committee.get_stake(batch.author())))
            .collect::<Vec<_>>();
        // Return the weighted median timestamp.
        weighted_median(timestamps_and_stakes)
    }

    /// Returns the subdag root of the batches.
    pub fn to_subdag_root(&self) -> Result<Field<N>> {
        // Prepare the leaves.
        let leaves = cfg_iter!(self.subdag)
            .map(|(_, batches)| batches.iter().flat_map(|batch| batch.batch_id().to_bits_le()).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        // Compute the subdag root.
        Ok(*N::merkle_tree_bhp::<SUBDAG_CERTIFICATES_DEPTH>(&leaves)?.root())
    }
}

impl<N: Network> Deref for SubdagV2<N> {
    type Target = BTreeMap<u64, IndexSet<BatchV2<N>>>;

    /// Returns the batches.
    fn deref(&self) -> &Self::Target {
        &self.subdag
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{network::MainnetV0, prelude::TestRng};

    use snarkvm_ledger_narwhal_batch_v2::test_helpers::*;

    use indexmap::{IndexSet, indexset};

    type CurrentNetwork = MainnetV0;

    /// Returns a sample subdag, sampled at random.
    pub fn sample_subdag_v2(rng: &mut TestRng) -> SubdagV2<CurrentNetwork> {
        // Use f=1 for a minimal BFT example: availability threshold = f+1 = 2, quorum threshold = 2f+1 = 3.
        const AVAILABILITY_THRESHOLD: usize = 2;
        const QUORUM_THRESHOLD: usize = 3;

        let mut subdag = BTreeMap::<u64, IndexSet<_>>::new();

        // Pick an arbitrary leader round.
        let leader_round = rng.random_range(2..u64::MAX - 2);

        // Leader round (r): exactly one batch with no previous batch IDs (round may be 1-or-above,
        // but for simplicity in tests we allow round >= 2 so previous_batch_ids is non-empty).
        // We sample with prior batch IDs drawn from random fields to satisfy the round >= 2 check.
        let leader_previous_ids =
            (0..AVAILABILITY_THRESHOLD).map(|_| Field::<CurrentNetwork>::rand(rng)).collect::<IndexSet<_>>();
        let leader_batch = sample_batch_v2_for_round_with_previous_batch_ids(leader_round, leader_previous_ids, rng);
        let leader_id = leader_batch.batch_id();
        subdag.insert(leader_round, indexset![leader_batch]);

        // Support round (r+1): AVAILABILITY_THRESHOLD batches, all referencing the leader.
        let mut support_ids = IndexSet::new();
        for _ in 0..AVAILABILITY_THRESHOLD {
            let batch = sample_batch_v2_for_round_with_previous_batch_ids(leader_round + 1, indexset![leader_id], rng);
            support_ids.insert(batch.batch_id());
            subdag.entry(leader_round + 1).or_default().insert(batch);
        }

        // Commit round (r+2): QUORUM_THRESHOLD batches, each referencing at least one support batch.
        for i in 0..QUORUM_THRESHOLD {
            // Each commit batch references one support batch (round-robin).
            let support_id = *support_ids.iter().nth(i % support_ids.len()).unwrap();
            let batch = sample_batch_v2_for_round_with_previous_batch_ids(leader_round + 2, indexset![support_id], rng);
            subdag.entry(leader_round + 2).or_default().insert(batch);
        }

        // Return the subdag.
        SubdagV2::from(subdag).unwrap() // Safe: the structure above satisfies all invariants.
    }

    /// Returns a list of sample subdags, sampled at random.
    pub fn sample_subdag_v2s(rng: &mut TestRng) -> Vec<SubdagV2<CurrentNetwork>> {
        let mut sample = Vec::with_capacity(10);
        for _ in 0..10 {
            sample.push(sample_subdag_v2(rng));
        }
        sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_ledger_narwhal_batch_v2::BatchV2;

    type CurrentNetwork = console::network::MainnetV0;

    const ITERATIONS: u64 = 100;

    #[test]
    fn test_max_batches() {
        // The maximum number of batches across all rounds in a block must fit in the Merkle tree.
        let max_batches_per_block =
            BatchV2::<CurrentNetwork>::MAX_GC_ROUNDS * CurrentNetwork::LATEST_MAX_CERTIFICATES() as usize;
        assert!(
            max_batches_per_block <= 2u32.checked_pow(SUBDAG_CERTIFICATES_DEPTH as u32).unwrap() as usize,
            "The maximum number of batches in a block is too large"
        );
    }

    #[test]
    fn test_weighted_median_simple() {
        let data = vec![(1, 10), (2, 10), (3, 10)];
        assert_eq!(weighted_median(data), 2);

        let data = vec![(5, 10)];
        assert_eq!(weighted_median(data), 5);

        let data = vec![(1, 10), (2, 30), (3, 20), (4, 40)];
        assert_eq!(weighted_median(data), 3);

        let data = vec![(100, 100), (200, 10000), (300, 500)];
        assert_eq!(weighted_median(data), 200);

        assert_eq!(weighted_median(vec![]), 0);

        let data = vec![(1, 1), (2, 1), (3, 1), (4, 1), (5, 1)];
        assert_eq!(weighted_median(data), 3);

        let data = vec![(1, 10), (2, 0), (3, 0), (4, 0), (5, 20), (6, 0), (7, 10)];
        assert_eq!(weighted_median(data), 5);
    }

    #[test]
    fn test_weighted_median_range() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let data: Vec<(i64, u64)> =
                (0..10).map(|_| (rng.random_range(1..100), rng.random_range(10..100))).collect();
            let min = data.iter().min_by_key(|x| x.0).unwrap().0;
            let max = data.iter().max_by_key(|x| x.0).unwrap().0;
            let median = weighted_median(data);
            assert!(median >= min && median <= max);
        }
    }

    #[test]
    fn test_weighted_median_scaled_weights() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let data: Vec<(i64, u64)> =
                (0..10).map(|_| (rng.random_range(1..100), rng.random_range(10..100) * 2)).collect();
            let scaled_data: Vec<(i64, u64)> = data.iter().map(|&(t, s)| (t, s * 10)).collect();
            assert_eq!(weighted_median(data), weighted_median(scaled_data));
        }
    }
}
