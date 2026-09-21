fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS");
    let abi = std::env::var("CARGO_CFG_TARGET_ENV").expect("Cargo target environment");
    if os == "macos" {
        // Node supplies the Node-API symbols when it loads this shared library.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    } else if os == "linux" && abi == "gnu" {
        // Rust TLS destructors must remain callable during thread shutdown.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-z,nodelete");
    }
}
