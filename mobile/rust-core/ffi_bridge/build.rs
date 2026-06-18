fn main() {
    uniffi_build::generate_scaffolding("src/ffi_bridge.udl").unwrap();
}
