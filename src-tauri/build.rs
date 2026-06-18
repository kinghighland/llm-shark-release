use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

fn hash_u64(mut h: u64, v: u64) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    if h == 0 {
        h = FNV_OFFSET;
    }
    let mut x = v;
    for _ in 0..8 {
        h ^= x & 0xff;
        h = h.wrapping_mul(FNV_PRIME);
        x >>= 8;
    }
    h
}

fn hash_str(mut h: u64, s: &str) -> u64 {
    for b in s.as_bytes() {
        h = hash_u64(h, *b as u64);
    }
    h
}

fn ui_fingerprint_and_watch(dir: &Path) -> u64 {
    let mut h: u64 = 0;

    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else {
            continue;
        };

        let mut children: BTreeMap<String, PathBuf> = BTreeMap::new();
        for ent in rd.flatten() {
            let p = ent.path();
            let k = p.to_string_lossy().to_string();
            children.insert(k, p);
        }

        for (k, p) in children {
            if p.is_dir() {
                stack.push(p);
                continue;
            }

            println!("cargo:rerun-if-changed={}", p.display());
            h = hash_str(h, &k);

            let Ok(m) = fs::metadata(&p) else {
                continue;
            };
            h = hash_u64(h, m.len());

            if let Ok(mt) = m.modified() {
                if let Ok(dur) = mt.duration_since(SystemTime::UNIX_EPOCH) {
                    h = hash_u64(h, dur.as_secs());
                    h = hash_u64(h, dur.subsec_nanos() as u64);
                }
            }
        }
    }

    h
}

fn emit_rerun_and_stamp_for_ui() {
    let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let ui_dir = PathBuf::from(manifest_dir).join("../ui");
    let fp = ui_fingerprint_and_watch(&ui_dir);
    println!("cargo:rustc-env=LLMSHARK_UI_FINGERPRINT={fp}");
}

#[cfg(windows)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    emit_rerun_and_stamp_for_ui();

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*" />
    </dependentAssembly>
  </dependency>
</assembly>
"#;

    fs::write(out_dir.join("app.manifest"), manifest).expect("write app.manifest");

    // 嵌入图标和清单文件
    let rc_content = r#"1 24 "app.manifest"
1 ICON "icons/icon.ico"
"#;
    fs::write(out_dir.join("app.rc"), rc_content).expect("write app.rc");

    embed_resource::compile(
        out_dir.join("app.rc").to_str().expect("rc path"),
        embed_resource::NONE,
    );
}

#[cfg(not(windows))]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    emit_rerun_and_stamp_for_ui();
}
