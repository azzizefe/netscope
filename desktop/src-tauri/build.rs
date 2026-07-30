// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
fn main() {
    let attributes = tauri_build::Attributes::new();

    // On Windows, embed an application manifest. Both builds get one, but they
    // differ in a single block.
    //
    // Release asks for Administrator rights, so Windows shows a UAC prompt on
    // every launch and the app always runs elevated — which is what its
    // IP-blocking feature needs, since installing firewall rules via `netsh`
    // requires elevation. Debug leaves that block out, because an elevated
    // binary cannot be launched from a non-elevated `cargo run` (os error 740).
    //
    // What debug must NOT leave out is the Common-Controls dependency below.
    // Declaring it is how a process gets version 6 of comctl32; without it
    // Windows loads 5.82 from System32, which does not export
    // `TaskDialogIndirect`. rfd — reached through tauri-plugin-dialog — imports
    // that symbol, so a binary missing the declaration dies with
    // STATUS_ENTRYPOINT_NOT_FOUND (0xc0000139) before `main` runs. It only
    // shows up when the linker keeps the dialog code, which is why
    // `cargo test -p netscope-desktop` was fine and `cargo test --workspace`
    // was not: the smaller build dropped the import entirely.
    #[cfg(windows)]
    let attributes = {
        let elevation = if std::env::var("PROFILE").as_deref() == Ok("release") {
            r#"  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
"#
        } else {
            ""
        };
        let manifest = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
{elevation}  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 / 11 -->
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}" />
      <!-- Windows 8.1 -->
      <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}" />
      <!-- Windows 8 -->
      <supportedOS Id="{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}" />
      <!-- Windows 7 -->
      <supportedOS Id="{{35138b9a-5d96-4fbd-8e2d-a2440225f93a}}" />
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
</assembly>"#
        );
        attributes.windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(manifest))
    };

    tauri_build::try_build(attributes).expect("failed to run tauri-build");

    // tauri-build compiles the manifest above into a resource archive and links
    // it into the binary — but only the binary. Test targets get no resource,
    // so they get no manifest, so they do not request comctl32 version 6, so
    // they die on the missing `TaskDialogIndirect` export described above.
    // Linking the same archive into the test targets is what makes
    // `cargo test --workspace` work on Windows.
    #[cfg(windows)]
    {
        let out = std::env::var("OUT_DIR").expect("OUT_DIR is always set");
        // The archive is named by the toolchain: GNU produces `libresource.a`,
        // MSVC `resource.lib`.
        // This is `rustc-link-arg`, not `-tests`: the crate's tests live in
        // `src/lib.rs`, so they build as the lib's unit-test target, and
        // `-tests` only covers a `tests/` directory. The app binary links the
        // archive twice as a result, which the linker discards as duplicate.
        for name in ["libresource.a", "resource.lib"] {
            let path = std::path::Path::new(&out).join(name);
            if path.exists() {
                println!("cargo:rustc-link-arg={}", path.display());
                break;
            }
        }
    }
}
