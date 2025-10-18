use serde_json::json;
use std::process::Command;
use std::time::Duration;
use std::{fs, io};

// Minimal sandbox: executes `python -c` code with rlimit-style constraints via prlimit (Linux),
// and denies networking by unsetting environment and using a separate temporary directory.
// WARNING: True isolation requires namespaces/seccomp; this is a pragmatic CLI for demo.

fn run_python(code: &str, timeout_sec: u64, stdout_cap: usize) -> serde_json::Value {
    let tmpdir = tempfile::tempdir().unwrap();
    let tmp_path = tmpdir.path().to_path_buf();
    // write runner file
    let runner = tmp_path.join("runner.py");
    fs::write(&runner, code).unwrap_or_default();

    // Try to use prlimit to restrict CPU/memory if available
    let python = std::env::var("PYTHON_BIN").unwrap_or("python3".to_string());
    let mut cmd = if which::which("prlimit").is_ok() {
        let mut c = Command::new("prlimit");
        c.arg("--cpu=")
            .arg(format!("{}", timeout_sec.max(1)))
            .arg("--as=")
            .arg(format!("{}", 256*1024*1024))
            .arg(&python)
            .arg("-I")
            .arg(runner.as_os_str());
        c
    } else {
        let mut c = Command::new(&python);
        c.arg("-I").arg(runner.as_os_str());
        c
    };

    cmd.current_dir(&tmp_path)
        .env("PYTHONHASHSEED", "0")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY");

    let output = match timeout_read::CommandExt::output_timeout(&mut cmd, Duration::from_secs(timeout_sec)) {
        Ok(Some(out)) => out,
        Ok(None) => {
            return json!({"ok": false, "error": "timeout"});
        }
        Err(e) => {
            return json!({"ok": false, "error": format!("spawn_error: {}", e)});
        }
    };

    let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.len() > stdout_cap { stdout.truncate(stdout_cap); }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    json!({
        "ok": output.status.success(),
        "code": output.status.code(),
        "stdout": stdout,
        "stderr": stderr,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("{}", json!({"error":"usage: sandbox run <timeout_sec> <stdout_cap> <base64_py>"}));
        return;
    }
    let cmd = &args[1];
    if cmd == "run" {
        if args.len() < 5 {
            println!("{}", json!({"error":"usage: sandbox run <timeout_sec> <stdout_cap> <base64_py>"}));
            return;
        }
        let timeout_sec: u64 = args[2].parse().unwrap_or(3);
        let stdout_cap: usize = args[3].parse().unwrap_or(200000);
        let code_b64 = &args[4];
        let bytes = base64::decode(code_b64).unwrap_or_default();
        let code = String::from_utf8_lossy(&bytes);
        let res = run_python(&code, timeout_sec, stdout_cap);
        println!("{}", res.to_string());
    } else {
        println!("{}", json!({"error":"unknown command"}));
    }
}
