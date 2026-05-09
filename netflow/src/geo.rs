//! Background GeoIP lookup for remote IPs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

const RATE_LIMIT_MS: u64 = 1500; // ~40 req/min, under ip-api's free quota
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
enum Entry {
    Pending,
    Resolved(String),
    Failed,
}

pub struct GeoCache {
    data: Mutex<HashMap<IpAddr, Entry>>,
    queue: UnboundedSender<IpAddr>,
}

impl GeoCache {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let cache = Arc::new(Self {
            data: Mutex::new(HashMap::new()),
            queue: tx,
        });
        tokio::spawn(worker(rx, Arc::clone(&cache)));
        cache
    }

    /// Returns the country code for `ip`, or an empty string if not yet
    /// resolved. The first call for an IP enqueues a background lookup.
    pub fn lookup(&self, ip: IpAddr) -> String {
        let mut data = self.data.lock().unwrap();
        match data.get(&ip) {
            Some(Entry::Resolved(c)) => return c.clone(),
            Some(_) => return String::new(),
            None => {}
        }
        data.insert(ip, Entry::Pending);
        drop(data);

        // Skip private ranges entirely so we don't waste API quota.
        if !is_public(&ip) {
            self.data
                .lock()
                .unwrap()
                .insert(ip, Entry::Resolved("LAN".to_string()));
            return "LAN".to_string();
        }

        let _ = self.queue.send(ip);
        String::new()
    }
}

#[derive(Deserialize)]
struct ApiResponse {
    #[serde(default, rename = "countryCode")]
    country_code: String,
    #[serde(default)]
    status: String,
}

async fn worker(mut rx: UnboundedReceiver<IpAddr>, cache: Arc<GeoCache>) {
    let mut last_call = tokio::time::Instant::now() - Duration::from_secs(60);

    while let Some(ip) = rx.recv().await {
        // Rate limit between API calls.
        let elapsed = last_call.elapsed();
        if elapsed < Duration::from_millis(RATE_LIMIT_MS) {
            tokio::time::sleep(Duration::from_millis(RATE_LIMIT_MS) - elapsed).await;
        }
        last_call = tokio::time::Instant::now();

        let url = format!("http://ip-api.com/json/{ip}?fields=status,countryCode");
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<ApiResponse> {
            let resp = ureq::get(&url).timeout(HTTP_TIMEOUT).call()?;
            Ok(resp.into_json::<ApiResponse>()?)
        })
        .await;

        let entry = match result {
            Ok(Ok(api)) if api.status == "success" && !api.country_code.is_empty() => {
                Entry::Resolved(api.country_code)
            }
            _ => Entry::Failed,
        };
        cache.data.lock().unwrap().insert(ip, entry);
    }
}

fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: &Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_broadcast() {
        return false;
    }
    if ip.is_unspecified() || ip.is_multicast() || ip.is_documentation() {
        return false;
    }
    let oct = ip.octets();
    // 100.64.0.0/10 (CGNAT) and 198.18.0.0/15 (benchmarking)
    if oct[0] == 100 && (oct[1] & 0xc0) == 64 {
        return false;
    }
    if oct[0] == 198 && (oct[1] == 18 || oct[1] == 19) {
        return false;
    }
    true
}

fn is_public_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let seg = ip.segments();
    // fc00::/7 unique-local, fe80::/10 link-local
    if (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    true
}
