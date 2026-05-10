# netflow

A Linux network monitor built as a Tauri desktop app, with a React/TypeScript UI and a Rust + eBPF backend.

## Structure

```
.
├── src/                  # React + TypeScript frontend (Vite)
│   ├── components/       # UI components (tables, charts, sidebar, firewall panel)
│   ├── lib/              # Frontend helpers (types, formatting, monitor hook, history)
│   ├── main.tsx          # React entry point
│   └── styles.css        # Tailwind styles
│
├── netflow/              # Tauri host app (Rust)
│   ├── src/              # loader, reader, filter, archiver, geo, proc_fs, state
│   ├── tauri.conf.json   # Tauri configuration
│   └── build.rs          # Builds and embeds the eBPF program
│
├── netflow-ebpf/         # eBPF program (kernel-side packet capture)
├── netflow-common/       # Shared types between user space and eBPF
│
├── Cargo.toml            # Rust workspace
├── package.json          # Frontend + Tauri CLI
├── vite.config.ts        # Vite config
└── index.html            # Vite entry
```

## Prerequisites

- Stable Rust: `rustup toolchain install stable`
- Nightly Rust (for eBPF): `rustup toolchain install nightly --component rust-src`
- bpf-linker: `cargo install bpf-linker`
- Node.js + npm
- Linux with eBPF support (the app must run with appropriate capabilities, e.g. `sudo`)

## Run

Install frontend dependencies once:

```shell
npm install
```

Start the app in development mode:

```shell
npm run tauri dev
```

Build a release bundle:

```shell
npm run tauri build
```
