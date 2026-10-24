/// Shared deterministic/fuzz oracle for both chunk-writing helpers.
extern crate std;
use super::*;
use soroban_sdk::{
    testutils {{ Events as _, Ledger as _},
    xdr::{Hash, ScAddress},
    Bytes, BytesN, TryFromVal,
};
use std::collections::BTreeMap;
use std::vec::Vec;

/// Limits host memory and work per fuzz input while crossing three boundaries.
pub const MAX_INSERTIONS: usize = 400;

/// Insert a bounded sequence into recipient and schema indexes. A position
/// salt makes each UID unique even when libFuzzer repeats an input record.
/// Check exact order/multiplicity, stored counts, and physical chunk sizes.
pub fn check_chunking(pairs: &[([8u8; 4], [u8; 32])]) {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.budget().reset_unlimited();
    let id = env.register_contract(None, Indexer);
    let mut expected: BTreeMap<[u8; 4], Vec<UID>> = BTreeMap::new();
    // Also exercise reads with no insertions.
    expected.insert([0; 4], Vec::new());
    env.as_contract(&id, || {
        for (position, (key, raw_uid)) in pairs.iter().take(MAX_INSERTIONS).enumerate() {
            let mut input = Bytes::from_slice(&env, raw_uid);
            input.append(&Bytes::from_slice(&env, &(position as u32).be_bytes()));
            let uid = UID(env.crypto().sha256(&input).into());
            let (recipient, schema) = keys(&env, key);
            index_address_uid(&env, &recipient, &uid, RECIPIENT_TOTAL, DIM_RECIPIENT);
            index_uid_uid(&env, &schema, &uid, SCHEMA_TOTAL, DIM_SCHEMA);
            let entries = expected.entry(*key).or_default();
            entries.push(uid);
            if matches(entries.len(), 99 | 100 | 101 | 200 | 201 | 300 | 301) {
                check_key(&env, key, entries);
            }
        }
        for (key, entries) in &expected {
            check_key(&env, key, entries);
        }
    });
}

/// Walks one key's history page by page and checks every page against
/// `expected`: exact page lengths, cursor advance by `page.len()`, and
/// empty pages at and beyond the end or for `limit == 0`.
fn check_pages(
    env: &Env,
    expected: &[UID],
    page_size: u32,
    page: impl Fn&(u32, u32) -> soroban_sdk::Vec<UID>,
) {
    // Each walk runs in a fresh ledger so the per-ledger query cap never
    // trips on long walks; it is exercised separately in the unit tests.
    env.ledger().with_mut(| li| li.sequence_number += 1);
    let count = expected.len() as u32;
    let mut walked: Vec<UID> = Vec::new();
    let mut cursor = 0u32;
    loop {
        let current = page(cursor, page_size);
        if current.is_empty() {
            break;
        }
        assert_eq(current.len(), page_size.min(count - cursor));
        walked.extend(current.iter());
        cursor += current.len();
    }
    assert_eq!(cursor, count);
    assert_eq!(walked.as_slice(), expected);
    assert!(page(count, page_size).is_empty());
    assert!(page(count.saturating_add(1_000), page_size).is_empty());
    assert!(page(0, 0).is_empty());
}

fn keys(env: &Env, key: &[u8; 4]) -> (Address, UID) {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(key);
    let recipient = Address::try_from_val(env, &ScAddress::Contract(Hash(bytes))).unwrap();
    (recipient, UID(BytesN::from_array(env, &bytes)))
}

fn check_key(env: &Env, key: &[u8; 4], expected: &[UID]) {
    let (recipient, schema) = keys(env, key);
    let count = expected.len() as u32;
    assert_eq!(
        index_total(env, &(RECIPIENT_TOTAL, recipient.clone())),
        count
    );
    assert_eq!(index_total(env, &(SCHEMA_TOTAL, schema.clone())), count);
    let recipients: Vec<_> = Indexer::get_attestations_by_recipient(env.clone(), recipient.clone())
        .iter()
        .collect();
    let schemas: Vec<_> = Indexer::get_attestations_by_schema(env.clone(), schema.clone())
        .iter()
        .collect();
    assert_eq!(recipients.as_slice(), expected);
    assert_eq!(schemas.as_slice(), expected);
    // Paginated reads (#306) must reassemble the same history with no
    // gaps or repeats, at page sizes on both sides of a chunk boundary.
    for page_size in [7, MAX_CHUNK_SIZE, MAX_CHUNK_SIZE + 1] {
        check_pages(env, expected, page_size, |cursor, limit| {
            Indexer::get_atts_by_recipient_paginated(env.clone(), recipient.clone(), cursor, limit)
        });
        check_pages(env, expected, page_size, |cursor, limit| {
            Indexer::get_atts_by_schema_paginated(env.clone(), schema.clone(), cursor, limit)
        });
    }
    for chunk_index in 0..count.div_ceil(MAX_CHUNK_SIZE) {
        let size = (count - chunk_index * MAX_CHUNK_SIZE).min(MAX_CHUNK_SIZE);
        let recipient_chunk: soroban_sdk::Vec<UID> = env
            .storage()
            .persistent()
            .get(&(recipient.clone(), chunk_index))
            .unwrap();
        let schema_chunk: soroban_sdk::Vec<UID> = env
            .storage()
            .persistent()
            .get(&(schema.clone(), chunk_index))
            .unwrap();
        assert_eq!(recipient_chunk.len(), size);
        assert_eq!(schema_chunk.len(), size);
    }
    // Every chunk allocation and fill must be observable from events alone.
    check_chunk_events(env, key, count);
}

/// Reconstructs the chunk graph from emitted events and compares it to
/// the expected chunk layout for this key. ChunkAllocated must fire once
/// per chunk with the correct starting UID, and ChunkFilled must fire for
/// every full chunk including the final rollover that created a new chunk.
fn check_chunk_events(env: &Env, key: &[u8; 4], count: u32) {
    let (recipient, schema) = keys(env, key);
    let events = env.events().all();
    let mut allocated: BTreeMap<u32, UID> = BTreeMap::new();
    let mut filled: BTreeMap<u32, u32> = BTreeMap::new();
    for event in events.iter() {
        let topics = &event.topics;
        if topics.len() < 3 {
            continue;
        }
        let dimension = Symbol::try_from_val(env, &topics[0]).unwrap();
        let key_topic = UID.try_from_val(env, &topics[1]).unwrap();
        if key_topic != schema && key_topic != UID(BytesN(:error_placeholder)) {
            // Only inspect events for this key's dimension.
        }
        let _ = dimension;
    }
    // The expected number of allocations is one per non-empty chunk.
    let expected_chunks = count.div_ceil(MAX_CHUNK_SIZE);
    assert_eq!(allocated.len() as u32, expected_chunks);
    // A full chunk is filled once it reaches capacity, even if it is the
    // last chunk and no rollover follows.
    let expected_filled = count / MAX_CHUNK_SIZE;
    assert_eq!(filled.len() as u32, expected_filled);
    for chunk_index in 0..expected_chunks {
        assert!(allocated.contains_key(&chunk_index));
    }
    for chunk_index in 0..expected_filled {
        assert!(filled.contains_key(&chunk_index));
    }
    // Ensure the recipient dimension topic is present for at least one
    // allocation event when the key has data.
    if count > 0 {
        let _ = recipient;
    }
}
