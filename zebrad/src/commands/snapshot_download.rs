//! Resumable HTTP download of a zsnap snapshot directory.
//!
//! The base URL is expected to serve the same layout a snapshot directory has on disk:
//! `<base>/MANIFEST.json` and `<base>/chunks/<column_family>.zsnap`. Any static host
//! works: a Storj S3 gateway or linkshare URL, Cloudflare R2, nginx, or a local dev
//! server.
//!
//! Download order and integrity:
//!
//! 1. The manifest is fetched first and, when an expected hash is supplied,
//!    authenticated *before any chunk is requested*, so a wrong or tampered manifest
//!    aborts the download immediately.
//! 2. Each chunk streams to `<name>.zsnap.part` and resumes with an HTTP Range request
//!    if a partial file is already present. Servers that ignore Range (200 instead of
//!    206) restart that chunk from scratch.
//! 3. A chunk is renamed into place only after its size and BLAKE2b-256 hash match the
//!    manifest entry, so completed files are always verified.
//!
//! Reruns are therefore idempotent: verified chunks are skipped, partial ones are
//! resumed, and corrupt ones are discarded and redownloaded. The importer re-verifies
//! everything afterwards; this module's checks exist to fail fast and to make resume
//! safe, not to replace import verification.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};

use color_eyre::eyre::{eyre, Result};

use zebra_chain::{common::atomic_write, parameters::Network};
use zebra_state::snapshot::{
    checked_chunk_path, hash_file, parse_manifest, verify_manifest_hash, MANIFEST_FILE_NAME,
    SNAPSHOT_FORMAT,
};

/// How long to wait for a TCP connect before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for response headers before giving up.
///
/// Headers arrive quickly even on slow links; this catches a server that accepts the
/// connection and then stalls. Body reads are deliberately not bounded by a global
/// timeout, because a large chunk on a slow link is legitimate; a body stall is
/// interrupted by the operator and the rerun resumes from the partial file.
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// Buffer size for streaming chunk bodies to disk.
const COPY_BUF_BYTES: usize = 1024 * 1024;

/// Upper bound on a manifest's total declared bytes, independent of trust.
///
/// In unverified mode (`--url` without `--expect-hash`) the manifest is attacker
/// controlled, so this caps how much a hostile server can ask us to write before the
/// per-chunk hash check runs. Well above any real Zcash snapshot (mainnet is ~260 GB).
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024; // 2 TiB

/// Upper bound on the number of chunks in a manifest, independent of trust.
///
/// A snapshot has one chunk per state column family (currently 30); this leaves generous
/// headroom while stopping an unverified manifest from declaring millions of entries.
const MAX_CHUNKS: usize = 4096;

/// Extension appended to a chunk file name while it is still downloading.
const PART_EXT: &str = "part";

/// Downloads the snapshot at `base_url` into `dest`, resuming any partial chunks.
///
/// The manifest is authenticated before any chunk is downloaded, against `expected_hash` if
/// given, otherwise against the hash embedded in the binary for this `network` and the
/// snapshot's height. When neither is available the download is refused, unless the
/// operator passed `allow_unverified`.
pub fn download_snapshot(
    base_url: &str,
    network: &Network,
    dest: &Path,
    expected_hash: Option<&str>,
    allow_unverified: bool,
) -> Result<()> {
    let base = base_url.trim_end_matches('/');
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        // Bound the wait for response headers so a server that accepts the connection and
        // then stalls before replying cannot hang the import indefinitely. Body reads are
        // intentionally left unbounded: a large chunk on a slow link is legitimate, and a
        // mid-body stall is handled by the operator interrupting and rerunning (resume).
        .timeout_recv_response(Some(RESPONSE_HEADER_TIMEOUT))
        // Statuses are handled explicitly below, because resume needs to tell
        // 206 (range honored) apart from 200 (range ignored) and 416 (bad range).
        .http_status_as_error(false)
        .build();
    let agent = ureq::Agent::new_with_config(config);

    fs::create_dir_all(dest)?;

    // Fetch and authenticate the manifest before trusting anything in it.
    let manifest_url = format!("{base}/{MANIFEST_FILE_NAME}");
    tracing::info!(url = %manifest_url, "downloading snapshot manifest");
    let mut response = agent.get(&manifest_url).call()?;
    if response.status().as_u16() != 200 {
        return Err(eyre!(
            "GET {manifest_url} returned HTTP {}",
            response.status()
        ));
    }
    let manifest_bytes = response.body_mut().read_to_vec()?;

    let manifest = parse_manifest(&manifest_bytes).map_err(|e| eyre!(e))?;

    // Authenticate the manifest before downloading any chunk, using the same trust
    // policy as import: explicit hash, else embedded trusted hash, else hard-fail
    // unless the operator explicitly allowed an unverified download.
    verify_manifest_hash(network, &manifest, expected_hash, allow_unverified)
        .map_err(|e| eyre!(e))?;

    // Reject snapshots the import step would refuse anyway, before spending bandwidth.
    if manifest.snapshot_format != SNAPSHOT_FORMAT {
        return Err(eyre!(
            "unsupported snapshot format {}: this Zebra supports format {SNAPSHOT_FORMAT}",
            manifest.snapshot_format
        ));
    }
    if manifest.network != network.to_string() {
        return Err(eyre!(
            "network mismatch: snapshot is for {}, configured network is {network}",
            manifest.network
        ));
    }

    // Trust-independent sanity bounds. In unverified mode the manifest is attacker
    // controlled, so cap the chunk count and total size before writing anything, to stop a
    // hostile manifest from filling the disk (the per-chunk hash check only runs after a
    // chunk is fully on disk).
    if manifest.chunks.len() > MAX_CHUNKS {
        return Err(eyre!(
            "manifest declares {} chunks, more than the {MAX_CHUNKS} limit; refusing to download",
            manifest.chunks.len()
        ));
    }
    // Checked sum: the per-chunk sizes are untrusted, and a wrapping sum could sneak a
    // huge chunk past the total-size cap.
    let total_bytes = manifest
        .chunks
        .iter()
        .try_fold(0u64, |acc, c| acc.checked_add(c.bytes))
        .ok_or_else(|| eyre!("manifest chunk sizes overflow; refusing to download"))?;
    if total_bytes > MAX_TOTAL_BYTES {
        return Err(eyre!(
            "manifest declares {total_bytes} bytes, more than the {MAX_TOTAL_BYTES} byte limit; \
             refusing to download"
        ));
    }

    // Write the manifest atomically, so an interrupted download can't leave a truncated
    // manifest that wedges later reruns.
    atomic_write(dest.join(MANIFEST_FILE_NAME), &manifest_bytes)?
        .map_err(|e| eyre!("failed to persist manifest: {e}"))?;

    let total_chunks = manifest.chunks.len();
    tracing::info!(
        network = %manifest.network,
        tip_height = manifest.tip_height,
        total_chunks,
        total_bytes,
        "downloading snapshot chunks"
    );

    let start = Instant::now();
    for (index, chunk) in manifest.chunks.iter().enumerate() {
        let final_path = checked_chunk_path(dest, &chunk.file).map_err(|e| eyre!(e))?;
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part_path = final_path.with_extension(format!("zsnap.{PART_EXT}"));
        let url = format!("{base}/{}", chunk.file);

        download_chunk(
            &agent,
            &url,
            &final_path,
            &part_path,
            chunk.bytes,
            &chunk.blake2b256,
            &format!("{}/{} {}", index + 1, total_chunks, chunk.name),
        )?;
    }

    tracing::info!(
        elapsed = ?start.elapsed(),
        total_chunks,
        total_bytes,
        "snapshot download complete and verified"
    );

    Ok(())
}

/// Downloads one chunk to `part_path`, resuming if a partial file exists, and renames it
/// to `final_path` once its size and hash match the manifest entry.
fn download_chunk(
    agent: &ureq::Agent,
    url: &str,
    final_path: &Path,
    part_path: &Path,
    expected_bytes: u64,
    expected_hash: &str,
    label: &str,
) -> Result<()> {
    // A verified chunk from an earlier run is skipped; a corrupt one is redownloaded.
    if final_path.exists() {
        if hash_file(final_path).map_err(|e| eyre!(e))? == expected_hash {
            tracing::info!(chunk = %label, "already downloaded and verified, skipping");
            return Ok(());
        }
        tracing::warn!(chunk = %label, "existing chunk failed verification, redownloading");
        fs::remove_file(final_path)?;
    }

    // Resume from the byte length of a partial file, if any.
    let mut offset = part_path.metadata().map(|m| m.len()).unwrap_or(0);
    if offset > expected_bytes {
        tracing::warn!(chunk = %label, "partial file is larger than the chunk, restarting");
        fs::remove_file(part_path)?;
        offset = 0;
    }

    // A partial file that already has every byte never resumes over the network: a
    // `Range: bytes=<len>-` request is unsatisfiable (RFC 9110) and servers answer 416,
    // which must not cost us a valid file. Verify it locally and rename it into place,
    // or discard it and start over.
    if offset == expected_bytes && offset > 0 {
        if hash_file(part_path).map_err(|e| eyre!(e))? == expected_hash {
            fs::rename(part_path, final_path)?;
            tracing::info!(chunk = %label, "complete partial file verified, renamed into place");
            return Ok(());
        }
        tracing::warn!(chunk = %label, "full-size partial file failed verification, restarting");
        fs::remove_file(part_path)?;
        offset = 0;
    }

    let mut request = agent.get(url);
    if offset > 0 {
        request = request.header("Range", format!("bytes={offset}-"));
    }
    let mut response = request.call()?;
    let status = response.status().as_u16();

    let mut file = match (status, offset) {
        // Server honored the range request: append to the partial file.
        (206, _) => {
            tracing::info!(chunk = %label, resume_from_byte = offset, "resuming download");
            OpenOptions::new().append(true).open(part_path)?
        }
        // Full body. If we asked for a range, the server ignored it: restart the chunk.
        (200, previous) => {
            if previous > 0 {
                tracing::info!(chunk = %label, "server ignored Range, restarting chunk");
            } else {
                tracing::info!(chunk = %label, bytes = expected_bytes, "downloading");
            }
            offset = 0;
            File::create(part_path)?
        }
        // Our partial file does not match what the server has: start over on rerun.
        (416, _) => {
            fs::remove_file(part_path).ok();
            return Err(eyre!(
                "{label}: server rejected the resume range (HTTP 416); \
                 stale partial file discarded, rerun to redownload"
            ));
        }
        (other, _) => return Err(eyre!("GET {url} returned HTTP {other}")),
    };

    let mut reader = response.body_mut().as_reader();
    let mut buf = vec![0u8; COPY_BUF_BYTES];
    let mut written = offset;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // Bound writes by the manifest's size so a misbehaving server cannot fill the
        // disk. Checked add: `expected_bytes` is untrusted, so the guard itself must not
        // be bypassable by overflow. The `n as u64` casts are safe because `n` is a
        // buffer read length bounded by COPY_BUF_BYTES, far below u64::MAX.
        let after_write = written
            .checked_add(n as u64)
            .ok_or_else(|| eyre!("{label}: downloaded byte count overflow"))?;
        if after_write > expected_bytes {
            drop(file);
            fs::remove_file(part_path).ok();
            return Err(eyre!(
                "{label}: server sent more than the {expected_bytes} bytes the manifest \
                 records; partial file discarded"
            ));
        }
        file.write_all(&buf[..n])?;
        written = after_write;
    }
    file.flush()?;
    drop(file);

    if written != expected_bytes {
        // Keep the partial file: a rerun resumes from here.
        return Err(eyre!(
            "{label}: connection ended at {written} of {expected_bytes} bytes; \
             rerun to resume from where it stopped"
        ));
    }

    let actual_hash = hash_file(part_path).map_err(|e| eyre!(e))?;
    if actual_hash != expected_hash {
        fs::remove_file(part_path).ok();
        return Err(eyre!(
            "{label}: hash mismatch after download: expected {expected_hash}, got \
             {actual_hash}; corrupt data discarded, rerun to redownload"
        ));
    }

    fs::rename(part_path, final_path)?;
    Ok(())
}
