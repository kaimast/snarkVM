// Copyright 2024-2025 Aleo Network Foundation
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

use aleo_std::StorageMode;
use console::{
    account::{Address, PrivateKey},
    network::MainnetV0,
    prelude::*,
};
use ledger_narwhal::{BatchCertificate, BatchHeader, Subdag};
use ledger_store::ConsensusStore;
use snarkvm_ledger::{Block, Ledger};
use synthesizer::vm::VM;
use time::OffsetDateTime;

use indexmap::{IndexMap, IndexSet};
use std::collections::{BTreeMap, HashMap};

pub type CurrentNetwork = MainnetV0;

#[cfg(not(feature = "rocks"))]
pub type LedgerType<N> = ledger_store::helpers::memory::ConsensusMemory<N>;
#[cfg(feature = "rocks")]
pub type LedgerType<N> = ledger_store::helpers::rocksdb::ConsensusDB<N>;

/// Helper to build chains with custom structures for testing
pub struct TestChainBuilder {
    /// The keys of all validators.
    private_keys: Vec<PrivateKey<CurrentNetwork>>,
    /// The underlying ledger.
    ledger: Ledger<CurrentNetwork, LedgerType<CurrentNetwork>>,
    /// The round containing the leader certificate for the most recent block we generated.
    last_block_round: u64,
    /// The batch certificates of the last round we generated.
    round_to_certificates: HashMap<u64, IndexMap<usize, BatchCertificate<CurrentNetwork>>>,
    /// The batch certificate of the last leader (if any).
    previous_leader_certificate: Option<BatchCertificate<CurrentNetwork>>,
    /// The height of the last block we created.
    current_height: u64,
    /// The last batch for each committee member that was included in a block.
    /// Maps the author's index to a round number.
    last_batch: HashMap<usize, u64>,
    /// The last batch of a validator that was included in a block
    last_committed_batch: HashMap<usize, u64>,
    /// The start of the test chain
    genesis_block: Block<CurrentNetwork>,
}

/// Additional options you can pass to the builder when generating blocks.
#[derive(Default)]
pub struct BlockOptions {
    /// Do not include votes to the previous leader certificate
    pub skip_votes: bool,
    /// Do not generate certificates for the specific node indicies (to simulate a partition).
    pub skip_nodes: Vec<usize>,
}

impl TestChainBuilder {
    pub fn new(committee_size: usize, rng: &mut TestRng) -> Self {
        // Sample the genesis private key.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        // Initialize the store.
        let store = ConsensusStore::<_, LedgerType<_>>::open(StorageMode::new_test(None)).unwrap();
        // Create a genesis block with a seeded RNG to reproduce the same genesis private keys.
        let seed: u64 = rng.gen();
        let genesis_rng = &mut TestRng::from_seed(seed);
        let genesis_block = VM::from(store).unwrap().genesis_beacon(&private_key, genesis_rng).unwrap();

        // Extract the private keys from the genesis committee by using the same RNG to sample private keys.
        let genesis_rng = &mut TestRng::from_seed(seed);
        let private_keys = (0..committee_size).map(|_| PrivateKey::new(genesis_rng).unwrap()).collect();

        Self::from_genesis(private_keys, genesis_block)
    }

    /// Initialize the builder with the specified commitee and gensis block
    pub fn from_genesis(private_keys: Vec<PrivateKey<CurrentNetwork>>, genesis_block: Block<CurrentNetwork>) -> Self {
        // Initialize the ledger with the genesis block.
        let ledger = Ledger::<CurrentNetwork, LedgerType<CurrentNetwork>>::load(
            genesis_block.clone(),
            StorageMode::new_test(None),
        )
        .unwrap();

        Self {
            private_keys,
            ledger,

            genesis_block,
            current_height: 1,
            last_batch: Default::default(),
            last_committed_batch: Default::default(),
            last_block_round: 1,
            round_to_certificates: Default::default(),
            previous_leader_certificate: Default::default(),
        }
    }

    /// Create multiple blocks, with fully-connected DAGs.
    #[allow(dead_code)]
    pub fn generate_blocks(&mut self, num_blocks: usize, rng: &mut TestRng) -> Vec<Block<CurrentNetwork>> {
        self.generate_blocks_with_opts(num_blocks, &BlockOptions::default(), rng)
    }

    /// Create multiple blocks, with additional parameters
    pub fn generate_blocks_with_opts(
        &mut self,
        num_blocks: usize,
        options: &BlockOptions,
        rng: &mut TestRng,
    ) -> Vec<Block<CurrentNetwork>> {
        assert!(num_blocks > 0, "Need to build at least one block");

        (0..num_blocks).map(|_| self.generate_block_with_opts(options, rng)).collect()
    }

    /// Create a new block, with a fully-connected DAG.
    ///
    /// This will "fill in " any gaps left in earlier rounds from non participating nodes.
    pub fn generate_block(&mut self, rng: &mut TestRng) -> Block<CurrentNetwork> {
        self.generate_block_with_opts(&BlockOptions::default(), rng)
    }

    /// Same as `generate_block` but with additional options/parameters.
    pub fn generate_block_with_opts(&mut self, options: &BlockOptions, rng: &mut TestRng) -> Block<CurrentNetwork> {
        assert!(self.current_height > 0);
        assert!(options.skip_nodes.len() * 3 < self.private_keys.len());

        let block_height = self.current_height + 1;

        // SubDAGs can be at most GC roudns long.
        let mut round = if self.last_block_round < BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS as u64 {
            1
        } else {
            self.last_block_round - BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS as u64 + 2
        };

        // Create certificates for each round.
        loop {
            let mut created_anchor = false;

            let previous_certificate_ids = if round <= 1 {
                IndexSet::default()
            } else {
                self.round_to_certificates
                    .get(&(round - 1))
                    .unwrap()
                    .iter()
                    .filter_map(|(_, cert)| {
                        // If votes are skipped, remove previous leader cert from the set.
                        let skip = if let Some(leader) = &self.previous_leader_certificate {
                            options.skip_votes && leader.id() == cert.id()
                        } else {
                            false
                        };

                        if skip { None } else { Some(cert.id()) }
                    })
                    .collect()
            };

            let committee = self.ledger.get_committee_lookback_for_round(round).unwrap().unwrap_or_else(|| {
                panic!("No committee for round {round}");
            });

            for (key1_idx, private_key_1) in self.private_keys.iter().enumerate() {
                if options.skip_nodes.contains(&key1_idx) {
                    continue;
                }
                // Don't recreate batches that already exist.
                if self.last_batch.get(&key1_idx).unwrap_or(&0) >= &round {
                    continue;
                }

                let batch_header = BatchHeader::new(
                    private_key_1,
                    round,
                    OffsetDateTime::now_utc().unix_timestamp(),
                    committee.id(),
                    Default::default(),
                    previous_certificate_ids.clone(),
                    rng,
                )
                .unwrap();

                // Add signatures for the batch headers. This creates a fully connected DAG.
                let signatures = self
                    .private_keys
                    .iter()
                    .enumerate()
                    .filter(|&(key2_idx, _)| key1_idx != key2_idx)
                    .map(|(_, private_key_2)| private_key_2.sign(&[batch_header.batch_id()], rng).unwrap())
                    .collect();

                self.last_batch.insert(key1_idx, round);
                self.round_to_certificates
                    .entry(round)
                    .or_default()
                    .insert(key1_idx, BatchCertificate::from(batch_header, signatures).unwrap());

                if round % 2 == 0 {
                    let leader = committee.get_leader(round).unwrap();
                    if leader == Address::try_from(private_key_1).unwrap() {
                        created_anchor = true;
                    }
                }
            }

            // Anchor was confirmed by more than a third of the validators.
            if created_anchor && round % 2 == 0 && self.last_block_round < round {
                self.last_block_round = round;
                break;
            }

            round += 1;
        }

        let commit_round = round;

        // Construct the block
        let leader_committee = self.ledger.get_committee_lookback_for_round(round).unwrap().unwrap();
        let leader = leader_committee.get_leader(commit_round).unwrap();
        let (leader_idx, leader_certificate) =
            self.round_to_certificates.get(&commit_round).unwrap().iter().find(|(_, c)| c.author() == leader).unwrap();
        let leader_idx = *leader_idx;
        let leader_certificate = leader_certificate.clone();

        // Construct the subdag for the block.
        let mut subdag_map = BTreeMap::new();

        // Figure out what the earliest round for the subDAG could be.
        let start_round = if commit_round < BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS as u64 {
            1
        } else {
            commit_round - BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS as u64 + 2
        };

        for round in start_round..commit_round {
            let mut to_insert = IndexSet::new();
            for idx in 0..self.private_keys.len() {
                let cround = self.last_committed_batch.entry(idx).or_default();
                // Batch already included in another block
                if *cround >= round {
                    continue;
                }

                if let Some(cert) = self.round_to_certificates.entry(round).or_default().get(&idx) {
                    to_insert.insert(cert.clone());
                    *cround = round;
                }
            }
            if !to_insert.is_empty() {
                subdag_map.insert(round, to_insert);
            }
        }

        // Add the leader certificate.
        subdag_map.insert(commit_round, [leader_certificate.clone()].into());
        self.last_committed_batch.insert(leader_idx, commit_round);

        // Construct the block.
        let subdag = Subdag::from(subdag_map).unwrap();
        let block = self.ledger.prepare_advance_to_next_quorum_block(subdag, Default::default(), rng).unwrap();
        self.ledger.check_next_block(&block, rng).unwrap();

        // Update state.
        self.ledger.advance_to_next_block(&block).unwrap();
        self.previous_leader_certificate = Some(leader_certificate.clone());
        self.current_height = block_height;

        block
    }

    /// Return the genesis block associated with the test chain
    pub fn genesis_block(&self) -> &Block<CurrentNetwork> {
        &self.genesis_block
    }
}
