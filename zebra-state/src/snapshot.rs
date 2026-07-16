//! State snapshot export and import (assumeutxo-style fast sync).
//!
//! A snapshot is a directory containing:
//! - `MANIFEST.json`: snapshot metadata, including a BLAKE2b-256 hash of every chunk file.
//! - `chunks/<column_family>.zsnap`: the raw key-value pairs of one column family,
//!   in RocksDB sorted key order, framed as `[u32-le key_len][key][u32-le value_len][value]`
//!   after an 8-byte magic header.
//!
//! The "snapshot hash" published for a snapshot is the BLAKE2b-256 hash of the exact
//! `MANIFEST.json` file bytes. Verifying that hash transitively verifies every chunk.
//!
//! # No parallel serializer
//!
//! Export and import ride the state's own on-disk format. The column families come from the
//! authoritative [`STATE_COLUMN_FAMILIES_IN_CODE`] constant, and each value is the raw
//! `IntoDisk`/`FromDisk` bytes copied verbatim, so there is no second record serializer that
//! could drift from the database format version. Import additionally refuses a snapshot
//! whose column-family set differs from this build's (see `check_manifest_column_families`),
//! so a format change that adds or removes a column family is rejected, never silently
//! loaded.
//!
//! # Trust model
//!
//! Chunk contents are verified against the manifest, and the manifest against a
//! caller-supplied trusted hash: the same trust model as Zebra's hardcoded block
//! checkpoints. Additionally, the imported history tree and note commitment trees are
//! consensus-verified as soon as the first post-snapshot block is committed, because that
//! block's `hashBlockCommitments` header field must match the imported tree roots.
//!
//! # Consistency
//!
//! Exports open the database in read-only secondary mode, which sees a frozen view of the
//! primary database. This means exports are consistent even while the node keeps syncing.

use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use semver::Version;
use serde::{Deserialize, Serialize};

use zebra_chain::{block, parameters::Network};

use crate::{
    config::database_format_version_on_disk,
    constants::{state_database_format_version_in_code, STATE_DATABASE_KIND},
    service::finalized_state::{
        RawBytes, TypedColumnFamily, ZebraDb, STATE_COLUMN_FAMILIES_IN_CODE,
    },
    Config,
};

/// A boxed error for snapshot operations.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The version of the snapshot directory layout and hashing scheme.
///
/// Bumped to 2 when the snapshot's identity moved from a hash of the whole manifest to the
/// canonical hash over consensus-critical column families only (see
/// [`canonical_manifest_hash`] and benchmarks/differential-75600.md).
pub const SNAPSHOT_FORMAT: u32 = 2;

/// The magic bytes at the start of every chunk file.
const CHUNK_MAGIC: &[u8; 8] = b"ZSNAPv1\n";

/// Column families excluded from the canonical snapshot hash.
///
/// These hold non-consensus, block-derived metadata (reconstructable from the blocks) that
/// can legitimately differ between an independently-synced node and a snapshot-bootstrapped
/// one, so including them would stop two honest nodes at the same height from agreeing on the
/// hash. They are still exported, imported, and per-chunk hash-verified; they just do not
/// define the snapshot's identity. See benchmarks/differential-75600.md.
pub const NON_CONSENSUS_COLUMN_FAMILIES: &[&str] = &["block_info"];

/// The manifest file name inside a snapshot directory.
pub const MANIFEST_FILE_NAME: &str = "MANIFEST.json";

/// The chunk subdirectory name inside a snapshot directory.
const CHUNKS_DIR_NAME: &str = "chunks";

/// The number of key-value pairs written per database batch during import.
const IMPORT_BATCH_SIZE: usize = 10_000;

/// Sanity limit for a single key read from a chunk file.
const MAX_KEY_LEN: u32 = 16 * 1024 * 1024;

/// Sanity limit for a single value read from a chunk file.
const MAX_VALUE_LEN: u32 = 256 * 1024 * 1024;

/// The personalization string for snapshot BLAKE2b-256 hashes.
const HASH_PERSONALIZATION: &[u8] = b"ZebraSnapshotV1";

/// Trusted snapshot manifest hashes embedded in the binary, one list per network.
///
/// These are the snapshot analogue of Zebra's hardcoded block checkpoints: a snapshot whose
/// manifest hashes to the value listed for its height is trusted the same way a checkpointed
/// block is. They are meant to be regenerated and reviewed in-tree (see the snapshot-hashes
/// CI workflow) and shipped inside signed releases, so the trust root is the project's own
/// governance rather than any single publisher.
const MAINNET_SNAPSHOT_HASHES: &str = include_str!("snapshot/mainnet-snapshot-hashes.txt");
const TESTNET_SNAPSHOT_HASHES: &str = include_str!("snapshot/testnet-snapshot-hashes.txt");

/// Returns the embedded trusted manifest hash for `network` at `height`, if one is listed.
///
/// This lets an operator import without supplying `--expect-hash`: the binary already knows
/// the trusted hash for a blessed height, exactly like it knows checkpointed block hashes.
/// Looking the hash up by the manifest's declared height is safe, because a manifest that
/// lies about its height will not match the embedded hash for that height.
pub fn trusted_manifest_hash(network: &Network, height: u32) -> Option<String> {
    let list = if matches!(network, Network::Mainnet) {
        MAINNET_SNAPSHOT_HASHES
    } else if network.is_default_testnet() {
        TESTNET_SNAPSHOT_HASHES
    } else {
        // Regtest and custom testnets have their own chains, so hashes for the public
        // testnet must never verify their snapshots.
        return None;
    };

    parse_snapshot_hashes(list)
        .expect("embedded snapshot hash lists are compile-time constants validated by tests")
        .into_iter()
        .find(|(entry_height, _)| *entry_height == height)
        .map(|(_, hash)| hash)
}

/// Parses embedded snapshot-hash file lines into `(height, lowercase hash)` pairs.
///
/// Each entry is `<height> <64-char hex hash>`; blank lines and lines starting with `#` are
/// skipped. Malformed lines are hard errors: silently dropping one would silently delete a
/// trust anchor, downgrading blessed-height imports to the unverified path.
fn parse_snapshot_hashes(list: &str) -> Result<Vec<(u32, String)>, BoxError> {
    list.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut parts = line.split_whitespace();
            let (Some(height), Some(hash), None) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(format!("malformed snapshot hash line: {line:?}").into());
            };
            let height = height
                .parse()
                .map_err(|_| format!("invalid height in snapshot hash line: {line:?}"))?;
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("invalid hash in snapshot hash line: {line:?}").into());
            }
            Ok((height, hash.to_lowercase()))
        })
        .collect()
}

/// Metadata for one exported column family chunk file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkEntry {
    /// The column family name.
    pub name: String,

    /// The chunk file path, relative to the snapshot directory.
    pub file: String,

    /// The number of key-value records in the chunk.
    pub records: u64,

    /// The chunk file size in bytes.
    pub bytes: u64,

    /// The hex-encoded BLAKE2b-256 hash of the chunk file bytes.
    pub blake2b256: String,
}

/// The snapshot manifest, serialized as `MANIFEST.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// The snapshot directory layout and chunk framing version.
    pub snapshot_format: u32,

    /// The database format version that produced this snapshot, as a semver string.
    pub db_format_version: String,

    /// The network this snapshot was taken on: "Mainnet" or "Testnet".
    pub network: String,

    /// The finalized tip height at export time.
    pub tip_height: u32,

    /// The finalized tip block hash at export time, hex-encoded.
    pub tip_hash: String,

    /// Metadata and hashes for every exported column family.
    pub chunks: Vec<ChunkEntry>,
}

/// How a snapshot manifest was authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationSource {
    /// Verified against a hash the operator supplied explicitly.
    ExplicitHash,

    /// Verified against the hash embedded in this binary for the snapshot's
    /// network and height, like a block checkpoint.
    EmbeddedHash,

    /// Not verified: the operator explicitly allowed an unverified import.
    Unverified,
}

impl std::fmt::Display for VerificationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationSource::ExplicitHash => f.write_str("explicit --expect-hash"),
            VerificationSource::EmbeddedHash => f.write_str("embedded trusted hash"),
            VerificationSource::Unverified => f.write_str("UNVERIFIED"),
        }
    }
}

/// A summary of a completed export or import, for logging and display.
#[derive(Clone, Debug)]
pub struct SnapshotSummary {
    /// The snapshot directory.
    pub snapshot_dir: PathBuf,

    /// The hex-encoded BLAKE2b-256 hash of the manifest file bytes.
    pub manifest_hash: String,

    /// How the manifest was authenticated. Always `ExplicitHash` for exports:
    /// the exporter computed the hash itself.
    pub verification: VerificationSource,

    /// The snapshot tip height.
    pub tip_height: block::Height,

    /// The snapshot tip block hash.
    pub tip_hash: block::Hash,

    /// The total number of key-value records across all chunks.
    pub total_records: u64,

    /// The total size of all chunk files in bytes.
    pub total_bytes: u64,
}

/// Returns a BLAKE2b-256 hasher with the snapshot personalization.
fn snapshot_hasher() -> blake2b_simd::State {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(HASH_PERSONALIZATION)
        .to_state()
}

/// Returns the hex-encoded snapshot hash of `bytes`.
///
/// This is the hash function used for chunk files and for the published manifest hash,
/// exposed so downloaders can verify data without duplicating the personalization.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = snapshot_hasher();
    hasher.update(bytes);
    hex::encode(hasher.finalize().as_bytes())
}

/// Parses `MANIFEST.json` bytes into a [`SnapshotManifest`].
///
/// Exposed so downloaders can read the chunk list without a serde_json dependency.
pub fn parse_manifest(bytes: &[u8]) -> Result<SnapshotManifest, BoxError> {
    Ok(serde_json::from_slice(bytes)?)
}

/// The canonical hash that is a snapshot's identity: a BLAKE2b-256 over a deterministic,
/// language-agnostic text covering the snapshot's identity fields and the per-chunk hashes of
/// the consensus-critical column families only (excluding [`NON_CONSENSUS_COLUMN_FAMILIES`]).
///
/// Because it is a function of consensus state alone, two honest nodes at the same height
/// produce the same value, which is what the embedded trusted hashes and the reproducible
/// attestations rely on. The exact text is mirrored by `attestations/verify.sh` so an
/// independent tool can recompute it.
pub fn canonical_manifest_hash(manifest: &SnapshotManifest) -> String {
    use std::fmt::Write;

    let mut s = String::new();
    s.push_str("zsnap-canonical-v2\n");
    let _ = writeln!(s, "network={}", manifest.network);
    let _ = writeln!(s, "tip_height={}", manifest.tip_height);
    let _ = writeln!(s, "tip_hash={}", manifest.tip_hash);
    let _ = writeln!(s, "db_format_version={}", manifest.db_format_version);
    let _ = writeln!(s, "snapshot_format={}", manifest.snapshot_format);

    let mut chunks: Vec<&ChunkEntry> = manifest
        .chunks
        .iter()
        .filter(|c| !NON_CONSENSUS_COLUMN_FAMILIES.contains(&c.name.as_str()))
        .collect();
    chunks.sort_by(|a, b| a.name.cmp(&b.name));
    for c in chunks {
        let _ = writeln!(
            s,
            "chunk={},{},{},{}",
            c.name, c.records, c.bytes, c.blake2b256
        );
    }

    hash_bytes(s.as_bytes())
}

/// Resolves and enforces the manifest trust policy, shared by import and download.
///
/// An explicit `expected_hash` wins; otherwise the hash embedded in this binary for the
/// snapshot's (network, declared height) is used, like a block checkpoint. When neither
/// exists this is a hard error unless `allow_unverified` is set: the manifest author chooses
/// the declared height, so silently proceeding would let a hostile publisher pick any
/// non-blessed height and bypass verification entirely.
///
/// Returns the manifest hash and how it was verified.
pub fn verify_manifest_hash(
    network: &Network,
    manifest: &SnapshotManifest,
    expected_hash: Option<&str>,
    allow_unverified: bool,
) -> Result<(String, VerificationSource), BoxError> {
    let declared_height = manifest.tip_height;
    let manifest_hash = canonical_manifest_hash(manifest);

    let (source, expected) = match expected_hash {
        Some(expected) => (
            VerificationSource::ExplicitHash,
            expected.trim().to_lowercase(),
        ),
        None => match trusted_manifest_hash(network, declared_height) {
            Some(hash) => (VerificationSource::EmbeddedHash, hash),
            None if allow_unverified => {
                tracing::warn!(
                    %manifest_hash,
                    "using UNVERIFIED snapshot: no expected hash was given and no trusted \
                     hash is embedded for this network and height. Only do this with \
                     snapshots you exported yourself."
                );
                return Ok((manifest_hash, VerificationSource::Unverified));
            }
            None => {
                return Err(format!(
                    "cannot authenticate snapshot: no expected hash was given and no \
                     trusted hash is embedded for this network at height {declared_height}. \
                     Pass --expect-hash <hash> from a trusted source, or --allow-unverified \
                     for a snapshot you exported yourself."
                )
                .into());
            }
        },
    };

    if manifest_hash != expected {
        return Err(format!(
            "snapshot manifest hash mismatch: expected {expected} ({source}), got \
             {manifest_hash}. The snapshot may be corrupted or malicious, refusing to use it."
        )
        .into());
    }

    tracing::info!(%manifest_hash, %source, "snapshot manifest hash verified");
    Ok((manifest_hash, source))
}

/// Exports a snapshot of the finalized state configured in `config` into `snapshot_dir`.
///
/// Opens the database in read-only secondary mode, so it works on a running node's
/// cache directory, and sees a consistent frozen view of the state.
pub fn export_snapshot(
    config: &Config,
    network: &Network,
    snapshot_dir: &Path,
) -> Result<SnapshotSummary, BoxError> {
    let manifest_path = snapshot_dir.join(MANIFEST_FILE_NAME);
    if manifest_path.exists() {
        return Err(format!(
            "snapshot manifest already exists, refusing to overwrite: {}",
            manifest_path.display()
        )
        .into());
    }

    let db = ZebraDb::new(
        config,
        STATE_DATABASE_KIND,
        &state_database_format_version_in_code(),
        network,
        true,
        STATE_COLUMN_FAMILIES_IN_CODE
            .iter()
            .map(ToString::to_string),
        // Read-only mode: works on a running node, and can never modify the source state.
        true,
    )?;

    let (tip_height, tip_hash) = db
        .tip()
        .ok_or("cannot export a snapshot of an empty state: no finalized tip")?;

    // Refuse to export a database whose on-disk format is behind this binary's:
    // read-only mode skips format upgrades, so the data could be missing migrations
    // that the manifest's version stamp would falsely claim are present.
    let db_format_version = state_database_format_version_in_code();
    let on_disk_version = database_format_version_on_disk(
        config,
        STATE_DATABASE_KIND,
        db_format_version.major,
        network,
    )?
    .ok_or("no on-disk database format version found; run the node once, then export")?;
    if on_disk_version != db_format_version {
        return Err(format!(
            "cannot export: on-disk database format is {on_disk_version}, this Zebra uses \
             {db_format_version}. Run the node until format upgrades finish, then export."
        )
        .into());
    }

    tracing::info!(
        ?tip_height,
        %tip_hash,
        %db_format_version,
        "exporting state snapshot"
    );

    let chunks_dir = snapshot_dir.join(CHUNKS_DIR_NAME);
    fs::create_dir_all(&chunks_dir)?;

    let mut chunks = Vec::new();
    let mut total_records: u64 = 0;
    let mut total_bytes: u64 = 0;
    let start_time = Instant::now();

    for &cf_name in STATE_COLUMN_FAMILIES_IN_CODE {
        let cf = TypedColumnFamily::<RawBytes, RawBytes>::new(db.disk_db(), cf_name)
            .ok_or_else(|| format!("missing column family: {cf_name}"))?;

        let file_name = format!("{cf_name}.zsnap");
        let chunk_path = chunks_dir.join(&file_name);
        let file = File::create(&chunk_path)?;
        let mut writer = BufWriter::new(file);
        let mut hasher = snapshot_hasher();

        let mut records: u64 = 0;
        let mut bytes: u64 = 0;

        let mut write_hashed = |buf: &[u8], writer: &mut BufWriter<File>| -> Result<(), BoxError> {
            hasher.update(buf);
            writer.write_all(buf)?;
            Ok(())
        };

        write_hashed(CHUNK_MAGIC, &mut writer)?;
        // Cast is safe: these are in-memory buffer lengths, far below u64::MAX.
        bytes += CHUNK_MAGIC.len() as u64;

        for (key, value) in cf.zs_forward_range_iter(..) {
            let key = key.raw_bytes();
            let value = value.raw_bytes();

            // Framing: u32-le lengths. Keys and values are far below u32::MAX by construction.
            let key_len: u32 = key
                .len()
                .try_into()
                .map_err(|_| format!("key in {cf_name} exceeds 4 GiB, cannot frame it"))?;
            let value_len: u32 = value
                .len()
                .try_into()
                .map_err(|_| format!("value in {cf_name} exceeds 4 GiB, cannot frame it"))?;

            write_hashed(&key_len.to_le_bytes(), &mut writer)?;
            write_hashed(key, &mut writer)?;
            write_hashed(&value_len.to_le_bytes(), &mut writer)?;
            write_hashed(value, &mut writer)?;

            records += 1;
            // Casts are safe: both lengths fit in u32, checked by the try_into above.
            bytes += 8 + key.len() as u64 + value.len() as u64;
        }

        writer.flush()?;
        let hash = hex::encode(hasher.finalize().as_bytes());

        tracing::info!(%cf_name, records, bytes, "exported column family");

        total_records += records;
        total_bytes += bytes;
        chunks.push(ChunkEntry {
            name: cf_name.to_string(),
            file: format!("{CHUNKS_DIR_NAME}/{file_name}"),
            records,
            bytes,
            blake2b256: hash,
        });
    }

    // The secondary instance is frozen at open time, so the tip cannot have moved.
    // Check anyway, to catch any future changes to that assumption.
    let final_tip = db.tip();
    if final_tip != Some((tip_height, tip_hash)) {
        return Err(format!(
            "state tip moved during export, snapshot is inconsistent: \
             started at {tip_height:?} {tip_hash}, ended at {final_tip:?}"
        )
        .into());
    }

    let manifest = SnapshotManifest {
        snapshot_format: SNAPSHOT_FORMAT,
        db_format_version: db_format_version.to_string(),
        network: network.to_string(),
        tip_height: tip_height.0,
        tip_hash: tip_hash.to_string(),
        chunks,
    };

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    // Atomic write: a crash mid-write must not leave a truncated manifest, which would
    // wedge the snapshot directory (export refuses to overwrite an existing manifest).
    zebra_chain::common::atomic_write(manifest_path.clone(), &manifest_bytes)?
        .map_err(|e| format!("failed to persist manifest: {e}"))?;

    let manifest_hash = canonical_manifest_hash(&manifest);

    let elapsed = start_time.elapsed();
    tracing::info!(
        ?tip_height,
        %tip_hash,
        total_records,
        total_bytes,
        %manifest_hash,
        ?elapsed,
        "finished exporting state snapshot"
    );

    Ok(SnapshotSummary {
        snapshot_dir: snapshot_dir.to_path_buf(),
        manifest_hash,
        verification: VerificationSource::ExplicitHash,
        tip_height,
        tip_hash,
        total_records,
        total_bytes,
    })
}

/// Imports the snapshot in `snapshot_dir` into a fresh state database configured in `config`.
///
/// The manifest must authenticate: against `expected_manifest_hash` when provided, or the
/// hash embedded in this binary for the snapshot's network and height. When neither exists
/// the import is refused unless `allow_unverified` is set — only use unverified imports
/// with snapshots you exported yourself.
///
/// Refuses to import over an existing state database.
pub fn import_snapshot(
    config: &Config,
    network: &Network,
    snapshot_dir: &Path,
    expected_manifest_hash: Option<&str>,
    allow_unverified: bool,
) -> Result<SnapshotSummary, BoxError> {
    // Read and authenticate the manifest before trusting anything in it.
    let manifest_path = snapshot_dir.join(MANIFEST_FILE_NAME);
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;

    let manifest: SnapshotManifest = parse_manifest(&manifest_bytes)?;

    let (manifest_hash, verification) =
        verify_manifest_hash(network, &manifest, expected_manifest_hash, allow_unverified)?;

    if manifest.snapshot_format != SNAPSHOT_FORMAT {
        return Err(format!(
            "unsupported snapshot format {}: this Zebra supports format {SNAPSHOT_FORMAT}",
            manifest.snapshot_format
        )
        .into());
    }

    if manifest.network != network.to_string() {
        return Err(format!(
            "network mismatch: snapshot is for {}, configured network is {network}",
            manifest.network
        )
        .into());
    }

    // Require the exact database format version. Same-major-older-minor data would be
    // stamped with this binary's version file, so the pending minor format upgrades
    // would never run and the node would silently serve un-migrated data forever.
    let running_version = state_database_format_version_in_code();
    let snapshot_version = Version::parse(&manifest.db_format_version)?;
    if snapshot_version != running_version {
        return Err(format!(
            "database format version mismatch: snapshot is {snapshot_version}, this Zebra \
             uses {running_version}. Use a matching Zebra, or re-export the snapshot."
        )
        .into());
    }

    // Bind the snapshot to this build's exact set of column families. Export always writes
    // STATE_COLUMN_FAMILIES_IN_CODE, so a snapshot whose set differs was produced by a
    // different database format; loading it would leave column families missing or unknown
    // and silently desync the node. Refuse it here instead.
    check_manifest_column_families(&manifest)?;

    let tip_height = block::Height(manifest.tip_height);
    let tip_hash: block::Hash = manifest.tip_hash.parse()?;

    // An ephemeral state generates a fresh temporary path on every `db_path()` call, so
    // the imported data could never be found again. Refuse it up front.
    if config.ephemeral {
        return Err(
            "cannot import a snapshot into an ephemeral state: disable `ephemeral` in the \
             [state] config section"
                .into(),
        );
    }

    // Refuse to touch an existing database.
    let final_db_path = config.db_path(STATE_DATABASE_KIND, running_version.major, network);
    if final_db_path.exists() {
        return Err(format!(
            "target state database already exists, refusing to import over it: {}. \
             Delete it first if you want to replace it with the snapshot.",
            final_db_path.display()
        )
        .into());
    }

    // Verify every chunk hash before writing anything to the database.
    tracing::info!("verifying snapshot chunk hashes");
    for chunk in &manifest.chunks {
        let chunk_path = checked_chunk_path(snapshot_dir, &chunk.file)?;
        let actual = hash_file(&chunk_path)?;
        if actual != chunk.blake2b256 {
            return Err(format!(
                "chunk hash mismatch for column family {}: expected {}, got {actual}. \
                 The snapshot is corrupted, refusing to import.",
                chunk.name, chunk.blake2b256
            )
            .into());
        }
    }
    tracing::info!(chunks = manifest.chunks.len(), "all chunk hashes verified");

    let start_time = Instant::now();

    // Build the database in a temporary directory inside the cache dir (same filesystem)
    // and rename it into place only after every check passes. This makes the import
    // atomic: a crash or Ctrl-C can never leave a half-populated database that a later
    // `zebrad start` would open as real state. It also guarantees the fresh database is
    // created in a cache directory containing no previous-major database, so
    // `ZebraDb::new` can never rename-and-reuse an old state underneath the import.
    fs::create_dir_all(&config.cache_dir)?;
    let tmp_cache = tempfile::Builder::new()
        .prefix("zsnap-import-")
        .tempdir_in(&config.cache_dir)?;
    let tmp_config = Config {
        cache_dir: tmp_cache.path().to_path_buf(),
        ..config.clone()
    };

    let mut db = ZebraDb::new(
        &tmp_config,
        STATE_DATABASE_KIND,
        &running_version,
        network,
        false,
        STATE_COLUMN_FAMILIES_IN_CODE
            .iter()
            .map(ToString::to_string),
        false,
    )?;

    // Wait for the newly-created database's background format task before writing any
    // data: its validity checks must see the empty database, not a half-imported one.
    db.join_format_change_task();

    // Write the version file explicitly: the rename below must never publish a database
    // without one. The version file lives inside the database directory, so the rename
    // moves it along with the data.
    crate::config::hidden::write_database_format_version_to_disk(
        &tmp_config,
        STATE_DATABASE_KIND,
        running_version.major,
        &running_version,
        network,
    )?;

    let mut total_records: u64 = 0;
    let mut total_bytes: u64 = 0;

    for chunk in &manifest.chunks {
        let chunk_path = checked_chunk_path(snapshot_dir, &chunk.file)?;
        let records = import_chunk(&db, &chunk.name, &chunk_path)?;

        if records != chunk.records {
            return Err(format!(
                "record count mismatch for column family {}: manifest says {}, file has {records}",
                chunk.name, chunk.records
            )
            .into());
        }

        tracing::info!(cf_name = %chunk.name, records, "imported column family");
        total_records += records;
        total_bytes += chunk.bytes;
    }

    // Sanity checks: the imported state must contain the genesis block and the manifest tip.
    let imported_tip = db.tip();
    if imported_tip != Some((tip_height, tip_hash)) {
        return Err(format!(
            "imported state tip {imported_tip:?} does not match \
             snapshot manifest tip {tip_height:?} {tip_hash}"
        )
        .into());
    }

    if db.block_header(block::Height(0).into()).is_none() {
        return Err("imported state is missing the genesis block header".into());
    }

    let tip_header = db
        .block_header(tip_height.into())
        .ok_or("imported state is missing the tip block header")?;
    if tip_header.hash() != tip_hash {
        return Err(format!(
            "imported tip block header hashes to {}, expected {tip_hash}",
            tip_header.hash()
        )
        .into());
    }

    // Close the database before renaming its directory: RocksDB must not hold open
    // files across the move.
    drop(db);

    // Publish atomically. The rename only happens after every verification passed, so
    // the final path either has a complete verified database or nothing at all.
    if let Some(parent) = final_db_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_db_path = tmp_config.db_path(STATE_DATABASE_KIND, running_version.major, network);
    fs::rename(&tmp_db_path, &final_db_path).map_err(|e| {
        format!(
            "failed to move the imported database into place ({} -> {}): {e}",
            tmp_db_path.display(),
            final_db_path.display()
        )
    })?;

    let elapsed = start_time.elapsed();
    tracing::info!(
        ?tip_height,
        %tip_hash,
        total_records,
        total_bytes,
        ?elapsed,
        "finished importing state snapshot"
    );

    Ok(SnapshotSummary {
        snapshot_dir: snapshot_dir.to_path_buf(),
        manifest_hash,
        verification,
        tip_height,
        tip_hash,
        total_records,
        total_bytes,
    })
}

/// Checks that the manifest's column families are exactly the set this build defines in
/// [`STATE_COLUMN_FAMILIES_IN_CODE`].
///
/// Export writes one chunk per entry of that authoritative constant, so the values in a
/// snapshot are opaque `IntoDisk`/`FromDisk` bytes copied verbatim, with no parallel record
/// serializer that could drift from the database format. This check is the matching
/// guarantee on import: a snapshot from a different format (a missing or extra column
/// family) is refused rather than loaded into a node that expects a different layout.
fn check_manifest_column_families(manifest: &SnapshotManifest) -> Result<(), BoxError> {
    use std::collections::BTreeSet;

    let expected: BTreeSet<&str> = STATE_COLUMN_FAMILIES_IN_CODE.iter().copied().collect();
    let actual: BTreeSet<&str> = manifest.chunks.iter().map(|c| c.name.as_str()).collect();

    // Reject duplicate chunk entries before comparing sets: a duplicated name would let
    // a second chunk silently overlay the first while still passing the exact-set check.
    if manifest.chunks.len() != actual.len() {
        return Err(format!(
            "snapshot manifest lists {} chunks but only {} distinct column families; \
             duplicate chunk entries are not allowed",
            manifest.chunks.len(),
            actual.len()
        )
        .into());
    }

    if actual == expected {
        return Ok(());
    }

    let missing: Vec<&str> = expected.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&expected).copied().collect();

    Err(format!(
        "snapshot column families do not match this build's state format: \
         missing {missing:?}, unexpected {unexpected:?}. \
         The snapshot was produced by a different database format; re-export with a matching Zebra."
    )
    .into())
}

/// Resolves a manifest-relative chunk path, rejecting anything that could escape the
/// snapshot directory: absolute paths, `..` components, and (for Windows) rooted-but-
/// prefixless paths or drive prefixes, which `Path::is_absolute` does not catch but which
/// `Path::join` would honor.
///
/// Exposed so the snapshot downloader uses this exact check instead of its own copy:
/// a path-traversal fix must never land on one side only.
pub fn checked_chunk_path(snapshot_dir: &Path, relative: &str) -> Result<PathBuf, BoxError> {
    use std::path::Component;

    let path = Path::new(relative);
    let escapes = path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        });
    if escapes {
        return Err(format!("invalid chunk path in manifest: {relative}").into());
    }

    Ok(snapshot_dir.join(path))
}

/// Returns the hex-encoded snapshot hash of the file at `path`, streaming its contents.
pub fn hash_file(path: &Path) -> Result<String, BoxError> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = snapshot_hasher();
    let mut buf = vec![0u8; 1024 * 1024];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize().as_bytes()))
}

/// Imports one chunk file into the named column family, in batches.
/// Returns the number of records written.
fn import_chunk(db: &ZebraDb, cf_name: &str, chunk_path: &Path) -> Result<u64, BoxError> {
    let file =
        File::open(chunk_path).map_err(|e| format!("cannot open {}: {e}", chunk_path.display()))?;
    let mut reader = BufReader::new(file);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != CHUNK_MAGIC {
        return Err(format!("bad magic bytes in chunk file {}", chunk_path.display()).into());
    }

    let new_batch = || -> Result<_, BoxError> {
        let cf = TypedColumnFamily::<RawBytes, RawBytes>::new(db.disk_db(), cf_name)
            .ok_or_else(|| format!("missing column family: {cf_name}"))?;
        Ok(cf.new_batch_for_writing())
    };

    let mut batch = new_batch()?;
    let mut records: u64 = 0;
    let mut batched: usize = 0;

    loop {
        let key = match read_frame(&mut reader, MAX_KEY_LEN, chunk_path)? {
            Some(key) => key,
            // A clean EOF at a record boundary ends the chunk.
            None => break,
        };
        let value = read_frame(&mut reader, MAX_VALUE_LEN, chunk_path)?.ok_or_else(|| {
            format!(
                "truncated chunk file, key without value: {}",
                chunk_path.display()
            )
        })?;

        batch = batch.zs_insert(
            &RawBytes::new_raw_bytes(key),
            &RawBytes::new_raw_bytes(value),
        );
        records += 1;
        batched += 1;

        if batched >= IMPORT_BATCH_SIZE {
            batch.write_batch()?;
            batch = new_batch()?;
            batched = 0;
        }
    }

    if batched > 0 {
        batch.write_batch()?;
    }

    Ok(records)
}

/// Reads one length-prefixed frame from `reader`.
///
/// Returns `Ok(None)` on a clean EOF before the length prefix.
fn read_frame(
    reader: &mut impl Read,
    max_len: u32,
    chunk_path: &Path,
) -> Result<Option<Vec<u8>>, BoxError> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_le_bytes(len_bytes);
    if len > max_len {
        return Err(format!(
            "frame length {len} exceeds limit {max_len} in chunk file {}, \
             the snapshot is corrupted",
            chunk_path.display()
        )
        .into());
    }

    // Cast is safe: `len` fits in u32 and was bounds-checked against `max_len` above,
    // and usize is at least 32 bits on all supported targets.
    let mut frame = vec![0u8; len as usize];
    reader.read_exact(&mut frame).map_err(|e| {
        format!(
            "truncated frame in chunk file {}: {e}",
            chunk_path.display()
        )
    })?;

    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;

    use super::*;

    /// Frame a sequence of key/value pairs the way the exporter does, minus the leading
    /// magic bytes (which `import_chunk` consumes before it starts framing).
    fn frame_pairs(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (key, value) in pairs {
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
            buf.extend_from_slice(value);
        }
        buf
    }

    /// Compute the snapshot hash of some bytes, exactly as export/import do.
    fn snapshot_hash(bytes: &[u8]) -> String {
        let mut hasher = snapshot_hasher();
        hasher.update(bytes);
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Builds a manifest whose chunk names are exactly `cf_names`.
    fn manifest_with_cfs(cf_names: &[&str]) -> SnapshotManifest {
        SnapshotManifest {
            snapshot_format: SNAPSHOT_FORMAT,
            db_format_version: "28.0.0".to_string(),
            network: "Testnet".to_string(),
            tip_height: 1,
            tip_hash: "0".repeat(64),
            chunks: cf_names
                .iter()
                .map(|name| ChunkEntry {
                    name: name.to_string(),
                    file: format!("chunks/{name}.zsnap"),
                    records: 0,
                    bytes: 0,
                    blake2b256: String::new(),
                })
                .collect(),
        }
    }

    /// The embedded trusted-hash list resolves a real testnet entry, ignores comments, and
    /// returns nothing for unknown heights or networks. This is the checkpoint-style anchor
    /// that lets an operator import without supplying `--expect-hash`.
    #[test]
    fn embedded_trusted_hash_lookup() {
        let testnet = Network::new_default_testnet();

        assert_eq!(
            trusted_manifest_hash(&testnet, 75200).as_deref(),
            Some("a5db82a2b922f0d402b737088e824153aa15285959044199ee3554667f320666"),
            "the shipped testnet entry at height 75200 must resolve"
        );
        assert!(
            trusted_manifest_hash(&testnet, 999_999_999).is_none(),
            "an unlisted height has no embedded hash"
        );
        assert!(
            trusted_manifest_hash(&Network::Mainnet, 75200).is_none(),
            "mainnet has no blessed snapshot yet"
        );
        assert_eq!(
            parse_snapshot_hashes(TESTNET_SNAPSHOT_HASHES)
                .expect("the shipped testnet hash list is well formed")
                .len(),
            1,
            "the parser skips comments and blank lines"
        );
        assert!(
            parse_snapshot_hashes(MAINNET_SNAPSHOT_HASHES).is_ok(),
            "the shipped mainnet hash list is well formed"
        );

        // Malformed lines are hard errors, not silently dropped trust anchors.
        assert!(parse_snapshot_hashes("75200 nothex").is_err());
        assert!(parse_snapshot_hashes("notanumber a5db82a2").is_err());
        assert!(parse_snapshot_hashes("75200").is_err());

        // Regtest and custom testnets never resolve public-testnet hashes.
        assert!(
            trusted_manifest_hash(&Network::new_regtest(Default::default()), 75200).is_none(),
            "regtest must not trust public-testnet snapshot hashes"
        );
    }

    /// A manifest carrying exactly this build's column families is accepted; one that is
    /// missing a column family, or carries an unknown one, is refused. This is what stops a
    /// snapshot from a different database format being loaded silently.
    #[test]
    fn manifest_column_families_must_match_the_build() {
        // Exactly the code's set: accepted.
        let ok = manifest_with_cfs(STATE_COLUMN_FAMILIES_IN_CODE);
        assert!(check_manifest_column_families(&ok).is_ok());

        // Missing one column family: refused, and the error names it.
        let missing_set: Vec<&str> = STATE_COLUMN_FAMILIES_IN_CODE[1..].to_vec();
        let missing = manifest_with_cfs(&missing_set);
        let err = check_manifest_column_families(&missing)
            .expect_err("a snapshot missing a column family must be refused");
        assert!(err.to_string().contains(STATE_COLUMN_FAMILIES_IN_CODE[0]));

        // An unknown extra column family: refused.
        let mut extra_set: Vec<&str> = STATE_COLUMN_FAMILIES_IN_CODE.to_vec();
        extra_set.push("not_a_real_column_family");
        let extra = manifest_with_cfs(&extra_set);
        assert!(
            check_manifest_column_families(&extra).is_err(),
            "a snapshot with an unknown column family must be refused"
        );
    }

    /// The chunk framing is a faithful round trip: every framed key/value reads back
    /// byte-for-byte (including empty and binary data), and a clean EOF ends the stream.
    #[test]
    fn chunk_framing_round_trips() {
        let pairs: &[(&[u8], &[u8])] = &[
            (b"", b""),                          // empty key and value
            (b"key", b"value"),                  // ascii
            (&[0u8, 1, 2, 3, 255], &[7u8; 300]), // binary key, multi-byte-length value
        ];
        let bytes = frame_pairs(pairs);
        let mut reader = Cursor::new(bytes);
        let path = Path::new("test-chunk.zsnap");

        let mut read_back = Vec::new();
        while let Some(key) = read_frame(&mut reader, MAX_KEY_LEN, path).unwrap() {
            let value = read_frame(&mut reader, MAX_VALUE_LEN, path)
                .unwrap()
                .expect("a key is always followed by a value");
            read_back.push((key, value));
        }

        let expected: Vec<(Vec<u8>, Vec<u8>)> = pairs
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(read_back, expected);
    }

    /// A frame whose declared length exceeds the sanity limit is rejected before allocation.
    #[test]
    fn oversized_frame_is_rejected() {
        let bytes = (MAX_KEY_LEN + 1).to_le_bytes().to_vec();
        let mut reader = Cursor::new(bytes);
        assert!(
            read_frame(&mut reader, MAX_KEY_LEN, Path::new("bad.zsnap")).is_err(),
            "a frame longer than the limit must be rejected"
        );
    }

    /// A truncated frame (length prefix promises more bytes than exist) is an error, not a
    /// silent short read.
    #[test]
    fn truncated_frame_is_rejected() {
        let mut bytes = 10u32.to_le_bytes().to_vec(); // promises 10 bytes
        bytes.extend_from_slice(b"only5"); // supplies 5
        let mut reader = Cursor::new(bytes);
        assert!(
            read_frame(&mut reader, MAX_KEY_LEN, Path::new("trunc.zsnap")).is_err(),
            "a truncated frame must be rejected"
        );
    }

    /// The snapshot hash is a deterministic 32-byte (BLAKE2b-256) digest, and a single
    /// changed byte changes it. This is the basis of chunk integrity checks.
    #[test]
    fn snapshot_hash_is_deterministic_and_tamper_evident() {
        let data = b"consensus-critical state bytes";

        assert_eq!(
            snapshot_hash(data),
            snapshot_hash(data),
            "hashing the same bytes must be deterministic"
        );
        assert_eq!(
            snapshot_hash(data).len(),
            64,
            "BLAKE2b-256 is 32 bytes = 64 hex chars"
        );

        let mut tampered = data.to_vec();
        tampered[0] ^= 0x01;
        assert_ne!(
            snapshot_hash(data),
            snapshot_hash(&tampered),
            "a changed byte must change the hash"
        );
    }

    /// The published snapshot hash is a pure function of the manifest: re-serializing
    /// identical state yields the identical hash (so anyone can reproduce and verify a
    /// published hash), and any change to the manifest changes it (so a tampered snapshot
    /// cannot pass `--expect-hash`).
    #[test]
    fn manifest_hash_is_reproducible_and_tamper_evident() {
        let manifest = SnapshotManifest {
            snapshot_format: SNAPSHOT_FORMAT,
            db_format_version: "28.0.0".to_string(),
            network: "Testnet".to_string(),
            tip_height: 268_000,
            tip_hash: "000074f5eaa8cb07dfb08cd46d42d35e270df544eb5466ffaccfbac62c635f35"
                .to_string(),
            chunks: vec![ChunkEntry {
                name: "hash_by_height".to_string(),
                file: "chunks/hash_by_height.zsnap".to_string(),
                records: 268_001,
                bytes: 3_233_651,
                blake2b256: "629c4ef8c2280e82e73cd943b4c8d7d8d562f58d43669b65586feae5b74fd41d"
                    .to_string(),
            }],
        };

        // Reproducibility: identical manifest -> identical canonical hash.
        assert_eq!(
            canonical_manifest_hash(&manifest),
            canonical_manifest_hash(&manifest.clone())
        );

        // Tamper-evidence: flipping a consensus chunk's hash changes the canonical hash.
        let mut tampered = manifest.clone();
        tampered.chunks[0].blake2b256 = "00".repeat(32);
        assert_ne!(
            canonical_manifest_hash(&manifest),
            canonical_manifest_hash(&tampered)
        );
    }

    /// The canonical hash excludes non-consensus column families: a difference in
    /// `block_info` does not change it (so two independently-built nodes converge), but a
    /// difference in a consensus column family does. This is the fix for the divergence
    /// found by the from-genesis differential test.
    #[test]
    fn canonical_hash_ignores_non_consensus_metadata() {
        let base = SnapshotManifest {
            snapshot_format: SNAPSHOT_FORMAT,
            db_format_version: "28.0.0".to_string(),
            network: "Testnet".to_string(),
            tip_height: 75_600,
            tip_hash: "0".repeat(64),
            chunks: vec![
                ChunkEntry {
                    name: "sapling_note_commitment_tree".to_string(),
                    file: "chunks/sapling_note_commitment_tree.zsnap".to_string(),
                    records: 1,
                    bytes: 53,
                    blake2b256: "aa".repeat(32),
                },
                ChunkEntry {
                    name: "block_info".to_string(),
                    file: "chunks/block_info.zsnap".to_string(),
                    records: 75_601,
                    bytes: 4_000_000,
                    blake2b256: "bb".repeat(32),
                },
            ],
        };

        // Same consensus state, different block_info hash -> identical canonical hash.
        let mut other_block_info = base.clone();
        other_block_info.chunks[1].blake2b256 = "cc".repeat(32);
        assert_eq!(
            canonical_manifest_hash(&base),
            canonical_manifest_hash(&other_block_info),
            "block_info must not affect the canonical hash"
        );

        // Changing the consensus chunk DOES change the canonical hash.
        let mut other_consensus = base.clone();
        other_consensus.chunks[0].blake2b256 = "dd".repeat(32);
        assert_ne!(
            canonical_manifest_hash(&base),
            canonical_manifest_hash(&other_consensus),
            "a consensus column family must affect the canonical hash"
        );
    }
}
