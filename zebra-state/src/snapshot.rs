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
    time::{Duration, Instant},
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

/// The version of the snapshot directory layout and chunk framing format.
pub const SNAPSHOT_FORMAT: u32 = 1;

/// The magic bytes at the start of every chunk file.
const CHUNK_MAGIC: &[u8; 8] = b"ZSNAPv1\n";

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

/// How long to wait for the newly created database's format version file to be written.
const VERSION_FILE_WAIT: Duration = Duration::from_secs(30);

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
    } else {
        TESTNET_SNAPSHOT_HASHES
    };
    parse_snapshot_hashes(list)
        .find(|(entry_height, _)| *entry_height == height)
        .map(|(_, hash)| hash.to_lowercase())
}

/// Parses embedded snapshot-hash file lines into `(height, hash)` pairs.
///
/// Each entry is `<height> <hex-hash>`; blank lines and lines starting with `#` are skipped.
fn parse_snapshot_hashes(list: &str) -> impl Iterator<Item = (u32, &str)> {
    list.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let height = parts.next()?.parse().ok()?;
            let hash = parts.next()?;
            Some((height, hash))
        })
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

/// A summary of a completed export or import, for logging and display.
#[derive(Clone, Debug)]
pub struct SnapshotSummary {
    /// The snapshot directory.
    pub snapshot_dir: PathBuf,

    /// The hex-encoded BLAKE2b-256 hash of the manifest file bytes.
    pub manifest_hash: String,

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

    let db_format_version = state_database_format_version_in_code();

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
    fs::write(&manifest_path, &manifest_bytes)?;

    let mut hasher = snapshot_hasher();
    hasher.update(&manifest_bytes);
    let manifest_hash = hex::encode(hasher.finalize().as_bytes());

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
        tip_height,
        tip_hash,
        total_records,
        total_bytes,
    })
}

/// Imports the snapshot in `snapshot_dir` into a fresh state database configured in `config`.
///
/// If `expected_manifest_hash` is provided, the manifest file hash must match it exactly.
/// Without it, the import is *unverified*: only use unverified imports with snapshots
/// you exported yourself.
///
/// Refuses to import over an existing state database.
pub fn import_snapshot(
    config: &Config,
    network: &Network,
    snapshot_dir: &Path,
    expected_manifest_hash: Option<&str>,
) -> Result<SnapshotSummary, BoxError> {
    // Read and authenticate the manifest before trusting anything in it.
    let manifest_path = snapshot_dir.join(MANIFEST_FILE_NAME);
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;

    let manifest_hash = hash_bytes(&manifest_bytes);
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)?;

    // Resolve the hash to authenticate against. An explicit `--expect-hash` wins; otherwise
    // fall back to the hash embedded in this binary for the snapshot's (network, height),
    // which is trusted like a block checkpoint. Looking it up by the manifest's declared
    // height is safe: a lying height simply will not match the embedded hash for that height.
    let effective_hash = match expected_manifest_hash {
        Some(expected) => Some(("--expect-hash", expected.trim().to_lowercase())),
        None => trusted_manifest_hash(network, manifest.tip_height)
            .map(|hash| ("embedded trusted hash", hash)),
    };

    match &effective_hash {
        Some((source, expected)) => {
            if &manifest_hash != expected {
                return Err(format!(
                    "snapshot manifest hash mismatch: expected {expected} ({source}), \
                     got {manifest_hash}. The snapshot may be corrupted or malicious, \
                     refusing to import."
                )
                .into());
            }
            tracing::info!(%manifest_hash, source, "snapshot manifest hash verified");
        }
        None => {
            tracing::warn!(
                %manifest_hash,
                "importing UNVERIFIED snapshot: no --expect-hash was given and no trusted \
                 hash is embedded for this network and height. Only do this with snapshots \
                 you exported yourself."
            );
        }
    }

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

    let running_version = state_database_format_version_in_code();
    let snapshot_version = Version::parse(&manifest.db_format_version)?;
    if snapshot_version.major != running_version.major {
        return Err(format!(
            "database format major version mismatch: snapshot is {snapshot_version}, \
             this Zebra uses {running_version}. Re-export the snapshot with a matching Zebra."
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

    // Refuse to touch an existing database.
    let db_path = config.db_path(STATE_DATABASE_KIND, running_version.major, network);
    if db_path.exists() {
        return Err(format!(
            "target state database already exists, refusing to import over it: {}. \
             Delete it first if you want to replace it with the snapshot.",
            db_path.display()
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

    let db = ZebraDb::new(
        config,
        STATE_DATABASE_KIND,
        &running_version,
        network,
        false,
        STATE_COLUMN_FAMILIES_IN_CODE
            .iter()
            .map(ToString::to_string),
        false,
    )?;

    // The format version file is written by a background task for newly created databases.
    // Wait for it, so an interrupted import can't leave a versionless database behind.
    wait_for_version_file(config, network, &running_version)?;

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
fn checked_chunk_path(snapshot_dir: &Path, relative: &str) -> Result<PathBuf, BoxError> {
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

    let mut frame = vec![0u8; len as usize];
    reader.read_exact(&mut frame).map_err(|e| {
        format!(
            "truncated frame in chunk file {}: {e}",
            chunk_path.display()
        )
    })?;

    Ok(Some(frame))
}

/// Waits until the database format version file exists on disk with the running version.
///
/// Newly created databases write their version file from a background task.
fn wait_for_version_file(
    config: &Config,
    network: &Network,
    running_version: &Version,
) -> Result<(), BoxError> {
    let deadline = Instant::now() + VERSION_FILE_WAIT;

    loop {
        let on_disk = database_format_version_on_disk(
            config,
            STATE_DATABASE_KIND,
            running_version.major,
            network,
        )?;

        if let Some(version) = &on_disk {
            if version.major == running_version.major {
                return Ok(());
            }
        }

        if Instant::now() > deadline {
            return Err(format!(
                "timed out waiting for the database format version file, \
                 last saw {on_disk:?}, expected major version {}",
                running_version.major
            )
            .into());
        }

        std::thread::sleep(Duration::from_millis(100));
    }
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
            parse_snapshot_hashes(TESTNET_SNAPSHOT_HASHES).count(),
            1,
            "the parser skips comments and blank lines"
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

        let hash_manifest = |m: &SnapshotManifest| -> String {
            snapshot_hash(&serde_json::to_vec_pretty(m).unwrap())
        };

        // Reproducibility: identical manifest -> identical published hash.
        assert_eq!(hash_manifest(&manifest), hash_manifest(&manifest.clone()));

        // Tamper-evidence: flipping one chunk hash changes the manifest hash.
        let mut tampered = manifest.clone();
        tampered.chunks[0].blake2b256 = "00".repeat(32);
        assert_ne!(hash_manifest(&manifest), hash_manifest(&tampered));
    }
}
