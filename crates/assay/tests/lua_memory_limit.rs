// ASSAY_LUA_MEMORY_MB: unset keeps the historical 64 MiB, an explicit value
// sets the VM ceiling, and anything invalid refuses to start the VM.

use std::io::Write;
use std::process::{Command, Output};
use tempfile::NamedTempFile;

const MIB: u64 = 1024 * 1024;

fn write_lua(body: &str) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".lua").unwrap();
    f.write_all(body.as_bytes()).unwrap();
    f
}

fn run(script: &NamedTempFile, memory_mb: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_assay"));
    cmd.arg("run")
        .arg(script.path())
        .env_remove("ASSAY_LUA_MEMORY_MB");
    if let Some(value) = memory_mb {
        cmd.env("ASSAY_LUA_MEMORY_MB", value);
    }
    cmd.output().unwrap()
}

fn reported_limit(memory_mb: Option<&str>) -> u64 {
    let f = write_lua(
        r#"
        local m = assay_memory()
        if type(m.used_bytes) ~= "number" or m.used_bytes <= 0 then error("used_bytes missing") end
        if m.used_bytes > m.limit_bytes then error("used exceeds limit") end
        print("limit=" .. m.limit_bytes)
    "#,
    );
    let out = run(&f, memory_mb);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("limit="))
        .expect("limit line")
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn unset_keeps_64_mib() {
    assert_eq!(reported_limit(None), 64 * MIB);
}

#[test]
fn explicit_256_mib() {
    assert_eq!(reported_limit(Some("256")), 256 * MIB);
    assert_eq!(reported_limit(Some(" 256 ")), 256 * MIB);
}

#[test]
fn invalid_values_refuse_to_start() {
    let f = write_lua(r#"print("ran")"#);
    for bad in [
        "",
        "0",
        "15",
        "4097",
        "-1",
        "256MB",
        "2.5",
        "abc",
        "99999999999999999999999",
    ] {
        let out = run(&f, Some(bad));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{bad:?} must fail, stdout={stdout}");
        assert!(!stdout.contains("ran"), "{bad:?} must not run the script");
        assert!(
            stderr.contains("ASSAY_LUA_MEMORY_MB"),
            "{bad:?} names the variable: {stderr}"
        );
    }
}

#[test]
fn ceiling_is_enforced_at_the_configured_limit() {
    // ~96 MiB of live strings: past the 64 MiB default, inside 256 MiB.
    let f = write_lua(
        r#"
        local held = {}
        local ok, err = pcall(function()
          for i = 1, 96 do held[i] = string.rep(string.format("%08d", i), 131072) end
        end)
        print(ok and "fit" or ("oom:" .. tostring(err)))
    "#,
    );
    let small = run(&f, None);
    assert!(
        String::from_utf8_lossy(&small.stdout).contains("oom:"),
        "64 MiB must refuse 96 MiB"
    );
    let large = run(&f, Some("256"));
    assert!(
        String::from_utf8_lossy(&large.stdout).contains("fit"),
        "256 MiB must hold 96 MiB"
    );
}
