// aclc.rs - Adaptive Code Language Compiler (single-file, std-only)
// Build: rustc -O aclc.rs -o aclc
// Usage:
//   ./aclc --design --prompt <base64>
//   ./aclc --compile --source <base64>
// Output: JSON to stdout { language?, ir, python_code? }

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ts() -> u128 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() }

// Minimal Base64 decoder (standard alphabet, no whitespace)
fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut chunk: [u8; 4] = [0; 4];
    let mut idx = 0;
    let mut pad = 0;
    for &b in bytes {
        if b == b'=' { chunk[idx] = 0; idx += 1; pad += 1; }
        else if let Some(v) = b64_val(b) { chunk[idx] = v; idx += 1; }
        else { continue; }
        if idx == 4 {
            let triple = ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12) | ((chunk[2] as u32) << 6) | (chunk[3] as u32);
            out.push(((triple >> 16) & 0xFF) as u8);
            if pad < 2 { out.push(((triple >> 8) & 0xFF) as u8); }
            if pad < 1 { out.push((triple & 0xFF) as u8); }
            idx = 0; pad = 0;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn json_escape(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t") }

// Simple FNV-1a 64-bit hash for stability without external crates
fn stable_hash(parts: &[&str]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for p in parts {
        for &b in p.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= b'|' as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)[..12].to_string()
}

#[derive(Clone, Debug)]
struct IRNode { kind: String, text: String }

fn design_language(prompt: &str) -> String {
    // Produce a minimal language spec guided by prompt tokens
    let tokens: Vec<&str> = prompt.split_whitespace().collect();
    let name = format!("ACLC_{}", stable_hash(&[prompt]));
    let mut features = vec!["functions", "returns", "assign", "return", "for-range"]; // baseline
    if tokens.iter().any(|t| t.contains("reverse")) { features.push("slicing"); }
    let spec = format!(
        "{{\"language\":{{\"name\":\"{}\",\"features\":[{}],\"ts\":{}}}}}",
        name,
        features.iter().map(|f| format!("\"{}\"", f)).collect::<Vec<String>>().join(","),
        now_ts()
    );
    spec
}

fn parse_header(header: &str) -> (String, String, String) {
    // Expect: fn name(args) -> type
    let mut rest = header.trim();
    if rest.starts_with("fn ") { rest = &rest[3..]; }
    let mut name = String::new();
    let mut args = String::new();
    let mut ret = String::from("Any");
    if let Some(lp) = rest.find('(') {
        name = rest[..lp].trim().to_string();
        if let Some(rp) = rest[lp+1..].find(')') {
            args = rest[lp+1..lp+1+rp].trim().to_string();
            let after = rest[lp+1+rp+1..].trim();
            if let Some(pos) = after.find("->") {
                ret = after[pos+2..].trim().to_string();
            }
        }
    }
    (name, args, ret)
}

fn translate_line(l: &str) -> String {
    let ln = l.trim();
    if ln.starts_with("let ") {
        // let mut x: T = expr OR let x: T = expr
        let mut part = ln.trim_start_matches("let ").trim();
        if part.starts_with("mut ") { part = &part[4..]; }
        if let Some(eq) = part.find('=') {
            let left = part[..eq].trim();
            let right = part[eq+1..].trim();
            // left like: x: T
            let var = if let Some(col) = left.find(':') { left[..col].trim() } else { left };
            return format!("{} = {}", var, right);
        }
    }
    if ln.starts_with("for ") && ln.contains("..") && ln.contains("{") && ln.ends_with('}') {
        // for i in 0..n { inner }
        let body_start = ln.find('{').unwrap_or(ln.len());
        let head = ln[..body_start].trim();
        let inner = ln[body_start+1..ln.len()-1].trim();
        // head: for i in 0..n
        let mut parts = head.split_whitespace();
        parts.next(); // for
        let var = parts.next().unwrap_or("i");
        parts.next(); // in
        let range = parts.next().unwrap_or("0..1");
        let end = if let Some(dd) = range.find("..") { &range[dd+2..] } else { "1" };
        let inner_py = translate_line(inner);
        return format!("for {} in range({}):\n        {}", var, end, inner_py);
    }
    if ln.starts_with("return ") { return ln.to_string(); }
    ln.to_string()
}

fn compile_to_ir(src: &str) -> (Vec<IRNode>, String) {
    // Very small recognizer: MiniLang-like or Python def
    let mut nodes: Vec<IRNode> = Vec::new();
    let mut py = String::new();
    let trimmed = src.trim();
    if trimmed.starts_with("fn ") && trimmed.ends_with(':') {
        // MiniLang style: header + body lines
        let mut lines: Vec<&str> = trimmed.split('\n').filter(|l| !l.trim().is_empty()).collect();
        let header = lines.remove(0).trim();
        nodes.push(IRNode{ kind: "header".into(), text: header.into() });
        let body: Vec<String> = lines.into_iter().map(|l| l.trim().to_string()).collect();
        for b in &body { nodes.push(IRNode{ kind: "body".into(), text: b.into()}); }
        let (name, args, _ret) = parse_header(header);
        py.push_str(&format!("def {}({}):\n", name, args));
        if !body.is_empty() {
            for b in &body { py.push_str(&format!("    {}\n", b.replace("assign ", ""))); }
        } else {
            py.push_str("    pass\n");
        }
    } else if trimmed.starts_with("fn ") && trimmed.contains('{') && trimmed.ends_with('}') {
        // MetaLang-ish single function
        let header_end = trimmed.find('{').unwrap_or(0);
        let header = &trimmed[..header_end];
        nodes.push(IRNode{ kind: "header".into(), text: header.into()});
        let body = &trimmed[header_end+1..trimmed.len()-1];
        nodes.push(IRNode{ kind: "body".into(), text: body.trim().into()});
        let (name, args, _ret) = parse_header(header);
        let parts: Vec<&str> = body.split(';').map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
        py.push_str(&format!("def {}({}):\n", name, args));
        for l in parts { py.push_str(&format!("    {}\n", translate_line(l))); }
    } else if trimmed.starts_with("def ") {
        // Already Python
        nodes.push(IRNode{ kind: "python".into(), text: "def".into()});
        py.push_str(trimmed);
        if !py.ends_with('\n') { py.push('\n'); }
    } else {
        // Fallback: wrap as literal
        nodes.push(IRNode{ kind: "literal".into(), text: "raw".into()});
        py.push_str("\n");
    }
    (nodes, py)
}

fn to_json(nodes: &[IRNode], python: &str) -> String {
    let mut arr = String::new();
    for (i, n) in nodes.iter().enumerate() {
        if i > 0 { arr.push(','); }
        arr.push_str(&format!("{{\"kind\":\"{}\",\"text\":\"{}\"}}", json_escape(&n.kind), json_escape(&n.text)));
    }
    format!("{{\"ir\":{{\"nodes\":[{}]}},\"python_code\":\"{}\"}}", arr, json_escape(python))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut mode = String::new();
    let mut payload = String::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--design" => mode = "design".into(),
            "--compile" => mode = "compile".into(),
            "--prompt" => { i += 1; payload = args.get(i).cloned().unwrap_or_default(); },
            "--source" => { i += 1; payload = args.get(i).cloned().unwrap_or_default(); },
            _ => {}
        }
        i += 1;
    }

    if mode == "design" {
        let prompt = b64_decode(&payload);
        println!("{}", design_language(&prompt));
        return;
    }

    if mode == "compile" {
        let src = b64_decode(&payload);
        let (nodes, py) = compile_to_ir(&src);
        println!("{}", to_json(&nodes, &py));
        return;
    }

    eprintln!("Usage: --design --prompt <b64> | --compile --source <b64>");
    std::process::exit(2);
}
