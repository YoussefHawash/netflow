use std::sync::Arc;

use aya::maps::{MapData, RingBuf};
use netflow_common::PacketEvent;
use tokio::io::unix::AsyncFd;

use crate::Inner;

pub async fn run(ring_buf: RingBuf<MapData>, inner: Arc<Inner>) {
    let mut async_fd = match AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE) {
        Ok(f) => f,
        Err(e) => {
            log::error!("ring buffer AsyncFd init failed: {e}");
            return;
        }
    };

    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                log::error!("ring buffer poll failed: {e}");
                return;
            }
        };

        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < std::mem::size_of::<PacketEvent>() {
                continue;
            }
            let event: PacketEvent = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr() as *const PacketEvent)
            };

            if let Ok(mut state) = inner.state.lock() {
                state.ingest(&event);
            }
        }

        guard.clear_ready();
    }
}
