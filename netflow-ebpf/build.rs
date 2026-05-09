use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    // Best-effort cache invalidation: if `bpf-linker` is on PATH, tell cargo
    // to rebuild when the binary changes. If it isn't, don't panic here —
    // the real eBPF compile in the userspace `build.rs` (via aya-build) will
    // fail with a clear message if it's actually needed.
    if let Ok(bpf_linker) = which("bpf-linker") {
        if let Some(s) = bpf_linker.to_str() {
            println!("cargo:rerun-if-changed={s}");
        }
    }
}
