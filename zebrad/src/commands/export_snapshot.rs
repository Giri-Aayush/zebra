//! `export-snapshot` subcommand - exports a verifiable snapshot of the finalized state.
//!
//! Exports every state column family as raw key-value chunks, plus a `MANIFEST.json`
//! with per-chunk hashes. The printed manifest hash is the snapshot's identity:
//! importers pass it to `import-snapshot --expect-hash` to authenticate the snapshot.
//!
//! Opens the state in read-only secondary mode, so it can run against a live node.

use std::path::PathBuf;

use abscissa_core::{Application, Command, Runnable};
use clap::Parser;
use color_eyre::eyre::{eyre, Result};

use zebra_chain::parameters::Network;
use zebra_state::snapshot::export_snapshot;

use crate::prelude::APPLICATION;

/// Export a verifiable snapshot of Zebra's finalized chain state
#[derive(Command, Debug, Default, Parser)]
pub struct ExportSnapshotCmd {
    /// Directory to write the snapshot into. Must not already contain a manifest.
    #[clap(help = "directory to write the snapshot into")]
    out_dir: PathBuf,

    /// Path to Zebra's cached state, overriding the config file.
    #[clap(long, short, help = "path to directory with the Zebra chain state")]
    cache_dir: Option<PathBuf>,

    /// The network of the state to export, overriding the config file.
    #[clap(long, short, help = "the network of the chain state")]
    network: Option<Network>,
}

impl Runnable for ExportSnapshotCmd {
    /// `export-snapshot` sub-command entrypoint.
    #[allow(clippy::print_stdout)]
    fn run(&self) {
        match self.export() {
            Ok(()) => {}
            Err(error) => {
                tracing::error!("failed to export snapshot: {error}");
                std::process::exit(1);
            }
        }
    }
}

impl ExportSnapshotCmd {
    /// Export the snapshot using the configured state and network.
    #[allow(clippy::print_stdout)]
    fn export(&self) -> Result<()> {
        let mut config = APPLICATION.config().state.clone();
        if let Some(cache_dir) = self.cache_dir.clone() {
            config.cache_dir = cache_dir;
        }

        let network = self
            .network
            .clone()
            .unwrap_or_else(|| APPLICATION.config().network.network.clone());

        let summary = export_snapshot(&config, &network, &self.out_dir).map_err(|e| eyre!(e))?;

        println!("snapshot exported to: {}", summary.snapshot_dir.display());
        println!("network:              {network}");
        println!("tip height:           {}", summary.tip_height.0);
        println!("tip hash:             {}", summary.tip_hash);
        println!("total records:        {}", summary.total_records);
        println!("total bytes:          {}", summary.total_bytes);
        println!("manifest hash:        {}", summary.manifest_hash);
        println!();
        println!(
            "importers should verify with: \
             zebrad import-snapshot {} --expect-hash {}",
            summary.snapshot_dir.display(),
            summary.manifest_hash,
        );

        Ok(())
    }
}
