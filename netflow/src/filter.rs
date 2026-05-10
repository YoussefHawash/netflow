use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, MapData};
use serde::{Deserialize, Serialize};

pub const MODE_DENYLIST: u32 = 0;
pub const MODE_ALLOWLIST: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    Denylist,
    Allowlist,
}

impl FilterMode {
    fn raw(self) -> u32 {
        match self {
            Self::Denylist => MODE_DENYLIST,
            Self::Allowlist => MODE_ALLOWLIST,
        }
    }

    fn from_raw(v: u32) -> Self {
        if v == MODE_ALLOWLIST {
            Self::Allowlist
        } else {
            Self::Denylist
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterState {
    pub mode: FilterMode,
    pub pids: Vec<u32>,
    pub ipv4: Vec<String>,
}

pub struct FilterMaps {
    mode: Array<MapData, u32>,
    pids: HashMap<MapData, u32, u8>,
    ipv4: HashMap<MapData, u32, u8>,
    flows: HashMap<MapData, [u8; 12], u8>,
}

impl FilterMaps {
    pub fn new(
        mode: Array<MapData, u32>,
        pids: HashMap<MapData, u32, u8>,
        ipv4: HashMap<MapData, u32, u8>,
        flows: HashMap<MapData, [u8; 12], u8>,
    ) -> Self {
        Self {
            mode,
            pids,
            ipv4,
            flows,
        }
    }

    fn clear_flows(&mut self) {
        let keys: Vec<[u8; 12]> = self.flows.keys().filter_map(|r| r.ok()).collect();
        for k in keys {
            let _ = self.flows.remove(&k);
        }
    }

    pub fn set_mode(&mut self, mode: FilterMode) -> Result<()> {
        self.mode
            .set(0, mode.raw(), 0)
            .context("FILTER_MODE write")?;
        self.clear_flows();
        Ok(())
    }

    pub fn mode(&self) -> FilterMode {
        self.mode
            .get(&0, 0)
            .map(FilterMode::from_raw)
            .unwrap_or(FilterMode::Denylist)
    }

    pub fn add_pid(&mut self, pid: u32) -> Result<()> {
        self.pids
            .insert(pid, 0u8, 0)
            .context("FILTER_PIDS insert")?;
        self.clear_flows();
        Ok(())
    }

    pub fn remove_pid(&mut self, pid: u32) {
        let _ = self.pids.remove(&pid);
        self.clear_flows();
    }

    pub fn list_pids(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.pids.keys().filter_map(|r| r.ok()).collect();
        out.sort_unstable();
        out
    }

    pub fn clear_pids(&mut self) {
        for p in self.list_pids() {
            let _ = self.pids.remove(&p);
        }
        self.clear_flows();
    }

    pub fn add_ipv4(&mut self, addr: Ipv4Addr) -> Result<()> {
        self.ipv4
            .insert(Self::key(addr), 0u8, 0)
            .context("FILTER_IPS_V4 insert")?;
        self.clear_flows();
        Ok(())
    }

    pub fn remove_ipv4(&mut self, addr: Ipv4Addr) {
        let _ = self.ipv4.remove(&Self::key(addr));
        self.clear_flows();
    }

    pub fn list_ipv4(&self) -> Vec<Ipv4Addr> {
        let mut out: Vec<Ipv4Addr> = self
            .ipv4
            .keys()
            .filter_map(|r| r.ok())
            .map(|k| Ipv4Addr::from(k.to_be_bytes()))
            .collect();
        out.sort();
        out
    }

    pub fn clear_ipv4(&mut self) {
        for ip in self.list_ipv4() {
            let _ = self.ipv4.remove(&Self::key(ip));
        }
        self.clear_flows();
    }

    pub fn snapshot(&self) -> FilterState {
        FilterState {
            mode: self.mode(),
            pids: self.list_pids(),
            ipv4: self
                .list_ipv4()
                .into_iter()
                .map(|i| i.to_string())
                .collect(),
        }
    }

    fn key(addr: Ipv4Addr) -> u32 {
        u32::from_be_bytes(addr.octets())
    }
}
