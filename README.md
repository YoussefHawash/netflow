# netflow

A Linux network monitor built as a Tauri desktop app, with a React/TypeScript UI and a Rust + eBPF backend.

## Just run it

There's a prebuilt AppImage in the project root. One file, one command:

```shell
sudo ./netflow_0.1.0_aarch64.AppImage
```

That's it. Frontend, backend, and the eBPF program are all bundled inside. `sudo` is required because the app loads eBPF programs into the kernel.

## Or build it yourself

If you'd rather compile from source and go do shit:

### Prerequisites

- Stable Rust: `rustup toolchain install stable`
- Nightly Rust (for eBPF): `rustup toolchain install nightly --component rust-src`
- bpf-linker: `cargo install bpf-linker`
- Node.js + npm
- Linux with eBPF support

### Build

```shell
npm install
npm run tauri build
```

The single executable lands at:

```
target/release/bundle/appimage/netflow_0.1.0_aarch64.AppImage
```

For development with hot reload:

```shell
npm run tauri dev
```

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
