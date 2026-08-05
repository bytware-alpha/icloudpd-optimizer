fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=src/authorization_policy_macos.c");
        println!("cargo:rerun-if-changed=src/keychain_authorization_macos.c");
        cc::Build::new()
            .file("src/authorization_policy_macos.c")
            .compile("authorization_policy_macos");
        cc::Build::new()
            .file("src/keychain_authorization_macos.c")
            // The legacy Keychain ACL APIs are required for a code-requirement
            // access list; only their deprecation diagnostic is suppressed.
            .flag_if_supported("-Wno-deprecated-declarations")
            .compile("keychain_authorization_macos");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
}
