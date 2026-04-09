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

use super::*;

impl<N: Network> SubdagV2<N> {
    /// Shared functionality between `FromBytes` and `read_le_unchecked`.
    fn internal_read_le<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error(format!("Invalid subdag v2 version ({version})")));
        }

        // Read the number of rounds.
        let num_rounds = u32::read_le(&mut reader)?;
        // Ensure the number of rounds equals the commit window.
        if usize::try_from(num_rounds).ok() != Some(COMMIT_WINDOW) {
            return Err(error(format!("SubdagV2 must have exactly {COMMIT_WINDOW} rounds, got {num_rounds}")));
        }
        // Read the round batches.
        let mut subdag = BTreeMap::new();
        for _ in 0..num_rounds {
            // Read the round.
            let round = u64::read_le(&mut reader)?;
            // Read the number of batches.
            let num_batches = u16::read_le(&mut reader)?;
            // Ensure the number of batches is within bounds.
            if num_batches > N::LATEST_MAX_CERTIFICATES() {
                return Err(error(format!("Number of batches ({num_batches}) exceeds the maximum.",)));
            }
            // Read the batches.
            let mut batches = IndexSet::with_capacity(num_batches as usize);
            for _ in 0..num_batches {
                let batch = BatchV2::read_le_with_unchecked(&mut reader, unchecked)?;
                batches.insert(batch);
            }
            // Insert the round and batches.
            subdag.insert(round, batches);
        }

        // Return the subdag.
        if unchecked { Ok(Self::from_unchecked(subdag)) } else { Self::from(subdag).map_err(error) }
    }
}

impl<N: Network> FromBytes for SubdagV2<N> {
    /// Reads the subdag from the given buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::internal_read_le(reader, false)
    }

    /// Reads the subdag from the given buffer without performing any checks on the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::internal_read_le(reader, true)
    }
}

impl<N: Network> ToBytes for SubdagV2<N> {
    /// Writes the subdag to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;
        // Write the number of rounds.
        u32::try_from(self.subdag.len()).map_err(error)?.write_le(&mut writer)?;
        // Write the round batches.
        for (round, batches) in &self.subdag {
            // Write the round.
            round.write_le(&mut writer)?;
            // Write the number of batches.
            u16::try_from(batches.len()).map_err(error)?.write_le(&mut writer)?;
            // Write the batches.
            for batch in batches {
                batch.write_le(&mut writer)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        let rng = &mut TestRng::default();

        for expected in crate::test_helpers::sample_subdag_v2s(rng) {
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, SubdagV2::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, SubdagV2::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }
}
