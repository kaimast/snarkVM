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
#![allow(clippy::too_many_arguments)]

extern crate snarkvm_console as console;

mod bytes;
mod serialize;
mod string;
mod to_id;

use console::{
    account::{Address, PrivateKey, Signature},
    prelude::*,
    types::Field,
};
use snarkvm_ledger_narwhal_transmission_id::TransmissionID;

use core::hash::{Hash, Hasher};
use indexmap::IndexSet;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// A Mysticeti-style batch proposed by a single author. Unlike `BatchCertificate`,
/// a `BatchV2` carries only the author's own signature; quorum agreement is proven
/// structurally by the surrounding `SubdagV2` commit rule.
#[derive(Clone, PartialEq, Eq)]
pub struct BatchV2<N: Network> {
    /// The batch ID, defined as the hash of the author, round number, timestamp,
    /// committee ID, transmission IDs, and previous batch IDs.
    batch_id: Field<N>,
    /// The author of the batch.
    author: Address<N>,
    /// The round number.
    round: u64,
    /// The timestamp.
    timestamp: i64,
    /// The committee ID.
    committee_id: Field<N>,
    /// The set of transmission IDs.
    transmission_ids: IndexSet<TransmissionID<N>>,
    /// The batch IDs of the previous round (DAG edges).
    previous_batch_ids: IndexSet<Field<N>>,
    /// The signature of the batch ID from the author.
    signature: Signature<N>,
}

impl<N: Network> Hash for BatchV2<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.batch_id.hash(state);
    }
}

impl<N: Network> BatchV2<N> {
    /// The maximum number of rounds to store before garbage collecting.
    pub const MAX_GC_ROUNDS: usize = 100;
    /// The maximum number of transmissions in a batch.
    /// Note: This limit is set to 50 as part of safety measures to prevent DoS attacks.
    /// This limit can be increased in the future as performance improves. Alternatively,
    /// the rate of block production can be sped up to compensate for the limit set here.
    pub const MAX_TRANSMISSIONS_PER_BATCH: usize = 50;
}

impl<N: Network> BatchV2<N> {
    /// The maximum number of microcredits that can be spent on compute by the transactions in a batch.
    /// This implies the block spend limit is bounded at `batch_spend_limit * N::NUM_MAX_CERTIFICATES * MAX_GC_ROUNDS`.
    // TODO: div by 20 is temporary until we can dial in what the limit should be.
    pub fn batch_spend_limit(height: u32) -> u64 {
        consensus_config_value!(N, TRANSACTION_SPEND_LIMIT, height).unwrap() * Self::MAX_TRANSMISSIONS_PER_BATCH as u64
            / 20
    }
}

impl<N: Network> BatchV2<N> {
    /// Initializes a new batch.
    pub fn new<R: Rng + CryptoRng>(
        private_key: &PrivateKey<N>,
        round: u64,
        timestamp: i64,
        committee_id: Field<N>,
        transmission_ids: IndexSet<TransmissionID<N>>,
        previous_batch_ids: IndexSet<Field<N>>,
        rng: &mut R,
    ) -> Result<Self> {
        match round {
            0 | 1 => {
                // If the round is zero or one, then there should be no previous batch IDs.
                ensure!(previous_batch_ids.is_empty(), "Invalid round number, must not have previous batches");
            }
            // If the round is greater than one, then there should be at least one previous batch ID.
            _ => ensure!(!previous_batch_ids.is_empty(), "Invalid round number, must have previous batches"),
        }

        // Ensure that the number of transmissions is within bounds.
        ensure!(
            transmission_ids.len() <= Self::MAX_TRANSMISSIONS_PER_BATCH,
            "Invalid number of transmission IDs ({})",
            transmission_ids.len()
        );
        // Ensure that the number of previous batch IDs is within bounds.
        ensure!(
            previous_batch_ids.len() <= N::LATEST_MAX_CERTIFICATES() as usize,
            "Invalid number of previous batch IDs ({})",
            previous_batch_ids.len()
        );

        // Retrieve the address.
        let author = Address::try_from(private_key)?;
        // Compute the batch ID.
        let batch_id =
            Self::compute_batch_id(author, round, timestamp, committee_id, &transmission_ids, &previous_batch_ids)?;
        // Sign the batch ID.
        let signature = private_key.sign(&[batch_id], rng)?;
        // Return the batch.
        Ok(Self { batch_id, author, round, timestamp, committee_id, transmission_ids, previous_batch_ids, signature })
    }

    /// Initializes a batch from its constituent parts, verifying correctness.
    pub fn from(
        author: Address<N>,
        round: u64,
        timestamp: i64,
        committee_id: Field<N>,
        transmission_ids: IndexSet<TransmissionID<N>>,
        previous_batch_ids: IndexSet<Field<N>>,
        signature: Signature<N>,
    ) -> Result<Self> {
        match round {
            0 | 1 => {
                // If the round is zero or one, then there should be no previous batch IDs.
                ensure!(previous_batch_ids.is_empty(), "Invalid round number, must not have previous batches");
            }
            // If the round is greater than one, then there should be at least one previous batch ID.
            _ => ensure!(!previous_batch_ids.is_empty(), "Invalid round number, must have previous batches"),
        }

        // Ensure that the number of transmissions is within bounds.
        ensure!(
            transmission_ids.len() <= Self::MAX_TRANSMISSIONS_PER_BATCH,
            "Invalid number of transmission IDs ({})",
            transmission_ids.len()
        );
        // Ensure that the number of previous batch IDs is within bounds.
        ensure!(
            previous_batch_ids.len() <= N::LATEST_MAX_CERTIFICATES() as usize,
            "Invalid number of previous batch IDs ({})",
            previous_batch_ids.len()
        );

        // Compute the batch ID.
        let batch_id =
            Self::compute_batch_id(author, round, timestamp, committee_id, &transmission_ids, &previous_batch_ids)?;
        // Verify the signature.
        if !signature.verify(&author, &[batch_id]) {
            bail!("Invalid signature for the batch");
        }
        // Return the batch.
        Ok(Self::from_unchecked(
            author,
            batch_id,
            round,
            timestamp,
            committee_id,
            transmission_ids,
            previous_batch_ids,
            signature,
        ))
    }

    /// Initializes a batch from the given data, *without* checking it for correctness/consistency.
    pub fn from_unchecked(
        author: Address<N>,
        batch_id: Field<N>,
        round: u64,
        timestamp: i64,
        committee_id: Field<N>,
        transmission_ids: IndexSet<TransmissionID<N>>,
        previous_batch_ids: IndexSet<Field<N>>,
        signature: Signature<N>,
    ) -> Self {
        Self { author, batch_id, round, timestamp, committee_id, transmission_ids, previous_batch_ids, signature }
    }
}

impl<N: Network> BatchV2<N> {
    /// Returns the batch ID.
    pub const fn batch_id(&self) -> Field<N> {
        self.batch_id
    }

    /// Returns the author.
    pub const fn author(&self) -> Address<N> {
        self.author
    }

    /// Returns the round number.
    pub const fn round(&self) -> u64 {
        self.round
    }

    /// Returns the timestamp.
    pub const fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Returns the committee ID.
    pub const fn committee_id(&self) -> Field<N> {
        self.committee_id
    }

    /// Returns the transmission IDs.
    pub const fn transmission_ids(&self) -> &IndexSet<TransmissionID<N>> {
        &self.transmission_ids
    }

    /// Returns the batch IDs of the previous round.
    pub const fn previous_batch_ids(&self) -> &IndexSet<Field<N>> {
        &self.previous_batch_ids
    }

    /// Returns the signature.
    pub const fn signature(&self) -> &Signature<N> {
        &self.signature
    }
}

impl<N: Network> BatchV2<N> {
    /// Returns `true` if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.transmission_ids.is_empty()
    }

    /// Returns the number of transmissions in the batch.
    pub fn len(&self) -> usize {
        self.transmission_ids.len()
    }

    /// Returns `true` if the batch contains the specified `transmission ID`.
    pub fn contains(&self, transmission_id: impl Into<TransmissionID<N>>) -> bool {
        self.transmission_ids.contains(&transmission_id.into())
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{account::PrivateKey, network::MainnetV0, prelude::TestRng};

    use time::OffsetDateTime;

    type CurrentNetwork = MainnetV0;

    /// Returns a sample batch, sampled at random.
    pub fn sample_batch_v2(rng: &mut TestRng) -> BatchV2<CurrentNetwork> {
        sample_batch_v2_for_round(rng.random(), rng)
    }

    /// Returns a sample batch with a given round; the rest is sampled at random.
    pub fn sample_batch_v2_for_round(round: u64, rng: &mut TestRng) -> BatchV2<CurrentNetwork> {
        // Sample previous batch IDs.
        let previous_batch_ids = (0..10).map(|_| Field::<CurrentNetwork>::rand(rng)).collect::<IndexSet<_>>();
        // Return the batch.
        sample_batch_v2_for_round_with_previous_batch_ids(round, previous_batch_ids, rng)
    }

    /// Returns a sample batch with a given round and set of previous batch IDs; the rest is sampled at random.
    pub fn sample_batch_v2_for_round_with_previous_batch_ids(
        round: u64,
        previous_batch_ids: IndexSet<Field<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> BatchV2<CurrentNetwork> {
        // Sample a private key.
        let private_key = PrivateKey::new(rng).unwrap(); // Safe: rng is a valid source of randomness.
        // Return the batch.
        sample_batch_v2_for_round_and_key_with_previous_batch_ids(round, &private_key, previous_batch_ids, rng)
    }

    /// Returns a sample batch with a given round, author key, and set of previous batch IDs; the rest is sampled at random.
    pub fn sample_batch_v2_for_round_and_key_with_previous_batch_ids(
        round: u64,
        private_key: &PrivateKey<CurrentNetwork>,
        previous_batch_ids: IndexSet<Field<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> BatchV2<CurrentNetwork> {
        // Sample the committee ID.
        let committee_id = Field::<CurrentNetwork>::rand(rng);
        // Sample transmission IDs.
        let transmission_ids = snarkvm_ledger_narwhal_transmission_id::test_helpers::sample_transmission_ids(rng)
            .into_iter()
            .collect::<IndexSet<_>>();
        // Checkpoint the timestamp for the batch.
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        // Return the batch.
        BatchV2::new(private_key, round, timestamp, committee_id, transmission_ids, previous_batch_ids, rng).unwrap() // Safe: all inputs are well-formed.
    }

    /// Returns a list of sample batches, sampled at random.
    pub fn sample_batch_v2s(rng: &mut TestRng) -> Vec<BatchV2<CurrentNetwork>> {
        let mut sample = Vec::with_capacity(10);
        for _ in 0..10 {
            sample.push(sample_batch_v2(rng));
        }
        sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use console::network::{CanaryV0, MainnetV0, TestnetV0};

    #[test]
    fn test_max_synthesis_cost_below_batch_spend_limit() {
        fn max_synthesis_cost_valid<N: Network>() {
            let max_synthesis_cost = N::MAX_DEPLOYMENT_VARIABLES.saturating_add(N::MAX_DEPLOYMENT_CONSTRAINTS)
                * N::SYNTHESIS_FEE_MULTIPLIER
                / N::ARC_0005_COMPUTE_DISCOUNT;
            for (_, height) in N::CONSENSUS_VERSION_HEIGHTS().iter() {
                assert!(max_synthesis_cost < BatchV2::<N>::batch_spend_limit(*height));
            }
        }

        max_synthesis_cost_valid::<CanaryV0>();
        max_synthesis_cost_valid::<TestnetV0>();
        max_synthesis_cost_valid::<MainnetV0>();
    }
}
