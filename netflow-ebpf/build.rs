use which::which;

fn main() {
    if let Ok(bpf_linker) = which("bpf-linker") {
        if let Some(s) = bpf_linker.to_str() {
            println!("cargo:rerun-if-changed={s}");
        }
    }
}
