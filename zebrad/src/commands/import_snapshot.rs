//! `import-snapshot` subcommand - bootstraps a fresh state from an exported snapshot.
//!
//! With `--url`, first downloads the snapshot into `snapshot_dir` (resumable: rerun the
//! same command after an interruption and it picks up where it stopped).
//!
//! Verifies the snapshot manifest hash (if `--expect-hash` is provided), verifies every
//! chunk hash against the manifest, imports the raw key-value data into a fresh state
//! database, then runs sanity checks on the imported tip.
//!
//! After a successful import, start Zebra normally: it will sync from the snapshot tip.
//! The first block committed after the snapshot consensus-verifies the imported history
//! tree and note commitment trees, because its `hashBlockCommitments` header field must
//! match the imported tree roots.

use std::path::PathBuf;

use abscissa_core::{Application, Command, Runnable};
use clap::Parser;
use color_eyre::eyre::{eyre, Result};

use zebra_chain::parameters::Network;
use zebra_state::snapshot::{import_snapshot, VerificationSource};

use super::snapshot_download::download_snapshot;
use crate::prelude::APPLICATION;

/// Import a snapshot of Zebra's finalized chain state into a fresh state directory
#[derive(Command, Debug, Default, Parser)]
pub struct ImportSnapshotCmd {
    /// Directory containing the snapshot (with a MANIFEST.json).
    #[clap(help = "directory containing the snapshot to import \
                (with --url, the directory to download it into)")]
    snapshot_dir: PathBuf,

    /// Base URL to download the snapshot from before importing.
    #[clap(
        long,
        help = "download the snapshot from this base URL into <snapshot_dir> first; \
                expects <url>/MANIFEST.json and <url>/chunks/... (resumable: rerun \
                after an interruption to continue)"
    )]
    url: Option<String>,

    /// The expected manifest hash, from a trusted source.
    #[clap(
        long,
        help = "expected snapshot manifest hash from a trusted source. If omitted, the hash \
                embedded in this binary for the snapshot's network and height is used (like a \
                block checkpoint); if there is none either, the import is refused unless \
                --allow-unverified is passed"
    )]
    expect_hash: Option<String>,

    /// Allow importing a snapshot that cannot be authenticated.
    #[clap(
        long,
        help = "allow an import with no --expect-hash and no embedded trusted hash. \
                ONLY use this with snapshots you exported yourself"
    )]
    allow_unverified: bool,

    /// Path to Zebra's cached state, overriding the config file.
    #[clap(long, short, help = "path to directory for the new Zebra chain state")]
    cache_dir: Option<PathBuf>,

    /// The network of the snapshot, overriding the config file.
    #[clap(long, short, help = "the network of the chain state")]
    network: Option<Network>,
}

impl Runnable for ImportSnapshotCmd {
    /// `import-snapshot` sub-command entrypoint.
    #[allow(clippy::print_stdout)]
    fn run(&self) {
        match self.import() {
            Ok(()) => {}
            Err(error) => {
                tracing::error!("failed to import snapshot: {error}");
                std::process::exit(1);
            }
        }
    }
}

impl ImportSnapshotCmd {
    /// Import the snapshot into the configured state directory.
    #[allow(clippy::print_stdout)]
    fn import(&self) -> Result<()> {
        let mut config = APPLICATION.config().state.clone();
        if let Some(cache_dir) = self.cache_dir.clone() {
            config.cache_dir = cache_dir;
        }

        let network = self
            .network
            .clone()
            .unwrap_or_else(|| APPLICATION.config().network.network.clone());

        // With --url, fetch the snapshot into snapshot_dir before importing. The download
        // authenticates the manifest first (when --expect-hash is given) and verifies
        // every chunk, and reruns resume partial chunks instead of starting over.
        if let Some(url) = &self.url {
            download_snapshot(
                url,
                &network,
                &self.snapshot_dir,
                self.expect_hash.as_deref(),
                self.allow_unverified,
            )?;
        }

        let summary = import_snapshot(
            &config,
            &network,
            &self.snapshot_dir,
            self.expect_hash.as_deref(),
            self.allow_unverified,
        )
        .map_err(|e| eyre!(e))?;

        println!("snapshot imported from: {}", summary.snapshot_dir.display());
        println!("network:                {network}");
        println!("tip height:             {}", summary.tip_height.0);
        println!("tip hash:               {}", summary.tip_hash);
        println!("total records:          {}", summary.total_records);
        println!("manifest hash:          {}", summary.manifest_hash);
        // Report what actually happened, not what flags were passed: the library may
        // have authenticated against the embedded trusted hash without --expect-hash.
        println!("verification:           {}", summary.verification);

        if summary.verification == VerificationSource::Unverified {
            println!();
            println!(
                "WARNING: this import was NOT authenticated. \
                 Only use unverified imports with snapshots you exported yourself."
            );
        }

        println!();
        println!("start Zebra normally to sync from the snapshot tip");

        Ok(())
    }
}
