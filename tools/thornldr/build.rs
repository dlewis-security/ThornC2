fn main() {
    // Inject linker script using the absolute crate path so the script is
    // found regardless of the working directory cargo uses for the linker.
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/link.x");
}
