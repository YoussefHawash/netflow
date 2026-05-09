//! Per-snapshot XML archiver.
//!
//! Each `Monitor::snapshot()` call ships the just-completed epoch into this
//! task as an `ArchiveJob`. The archiver writes one XML file per job under:
//!
//!     <archive_dir>/YYYY-MM-DD/HHMMSS_<millis>.xml
//!
//! That keeps every observation that ever flowed through the live snapshot
//! persisted on disk, even if the user never polled fast enough to "see"
//! everything.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use serde::Serialize;
use tokio::{fs, sync::mpsc};

use crate::{ConnectionTraffic, HistoryBucket, ProcessTraffic};

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveJob {
    pub timestamp: DateTime<Local>,
    pub interface: String,
    pub received_rate: f64,
    pub sent_rate: f64,
    pub bucket: HistoryBucket,
    pub connections: Vec<ConnectionTraffic>,
    pub processes: Vec<ProcessTraffic>,
}

pub async fn run(mut rx: mpsc::UnboundedReceiver<ArchiveJob>, archive_dir: PathBuf) {
    while let Some(job) = rx.recv().await {
        if let Err(e) = write_job(&archive_dir, &job).await {
            log::warn!("archive write failed: {e}");
        }
    }
}

async fn write_job(archive_dir: &Path, job: &ArchiveJob) -> anyhow::Result<()> {
    let xml = quick_xml::se::to_string_with_root("snapshot", job)?;

    let date = job.timestamp.format("%Y-%m-%d").to_string();
    let time = job.timestamp.format("%H%M%S_%3f").to_string();
    let dir = archive_dir.join(date);
    fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("{time}.xml"));
    fs::write(path, xml).await?;
    Ok(())
}
