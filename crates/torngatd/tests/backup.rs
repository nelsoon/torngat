//! Backup and restore of a controller, with the real program.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn torngatd(args: &[&str], data: &Path, input: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_torngatd"))
        .args(args)
        .arg("--data")
        .arg(data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // It may refuse before it reads.
    let _ = c.stdin.take().unwrap().write_all(input.as_bytes());
    c.wait_with_output().unwrap()
}

fn ok(o: Output) -> String {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}

fn refused(o: Output, why: &str) {
    let e = String::from_utf8(o.stderr).unwrap();
    assert!(!o.status.success() && e.contains(why), "{e}");
}

fn code(out: &str) -> String {
    out.lines()
        .map(str::trim)
        .find(|l| l.len() == 49 && l.split('-').all(|g| g.len() == 4))
        .expect("a recovery code")
        .to_owned()
}

struct Running {
    child: Child,
    api: String,
    token: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run(data: &Path) -> Running {
    let free = || {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let (api, control, join) = (free(), free(), free());
    let child = Command::new(env!("CARGO_BIN_EXE_torngatd"))
        .args(["run", "--api", &api, "--control", &control, "--join", &join])
        .arg("--data")
        .arg(data)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let r = Running {
        child,
        api,
        token: std::fs::read_to_string(data.join("admin-token")).unwrap(),
    };
    let end = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(&r.api).is_err() {
        assert!(Instant::now() < end, "the API never came up");
        std::thread::sleep(Duration::from_millis(50));
    }
    r
}

impl Running {
    fn send(&self, token: &str, method: &str, path: &str, body: &str) -> (u16, Vec<u8>) {
        let mut s = TcpStream::connect(&self.api).unwrap();
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        let head = b.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let text = std::str::from_utf8(&b[..head]).unwrap();
        (text[9..12].parse().unwrap(), b[head + 4..].to_vec())
    }

    fn get(&self, path: &str) -> String {
        let (status, b) = self.send(&self.token, "GET", path, "");
        assert_eq!(status, 200, "{path}");
        String::from_utf8(b).unwrap()
    }

    /// When the node last registered.
    fn registered(&self) -> serde_json::Value {
        let v: serde_json::Value = serde_json::from_str(&self.get("/v1/platform/nodes")).unwrap();
        v["items"][0]["metadata"]["update_time"].clone()
    }

    fn post(&self, path: &str, body: &str) {
        let (status, b) = self.send(&self.token, "POST", path, body);
        assert_eq!(status, 200, "{path} {}", String::from_utf8_lossy(&b));
    }

    fn backup(&self) -> Vec<u8> {
        let (status, b) = self.send(&self.token, "GET", "/v1/platform/backup", "");
        assert_eq!(status, 200);
        b
    }

    /// Until the node is registered, so that the agent works.
    fn wait_node(&self) {
        let end = Instant::now() + Duration::from_secs(30);
        while !self.get("/v1/platform/nodes").contains("active") {
            assert!(Instant::now() < end, "n1 never registered");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

const TOKENS: &str = "/v1/platform/joinTokens";
const VOLUMES: &str = "/v1/orgs/acme/projects/web/volumes";

#[test]
fn backup_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let init = [
        "init",
        "--name",
        "n1",
        "--tpm",
        "optional",
        "--tpm-device",
        "none",
        "--allow-unsealed-root",
    ];
    let first = code(&ok(torngatd(&init, &a, "")));

    let r = run(&a);
    r.wait_node();
    r.post(
        "/v1/platform/storagePools?storage_pool_id=data",
        r#"{"spec": {"node": "n1", "driver": "lvm", "source": "data"}}"#,
    );
    r.post(
        "/v1/platform/volumeTypes?volume_type_id=fast",
        r#"{"spec": {"pools": ["data"]}}"#,
    );
    r.post(
        &format!("{VOLUMES}?volume_id=v1"),
        r#"{"spec": {"volume_type": "fast", "size_gib": 1}}"#,
    );
    let registered = r.registered();
    assert!(registered.is_string());
    let volumes = r.get(VOLUMES);
    let backup = r.backup();
    assert_eq!(r.send("wrong", "GET", "/v1/platform/backup", "").0, 401);
    let file = dir.path().join("backup");
    std::fs::write(&file, &backup).unwrap();
    // None of it can be read.
    let platform = std::fs::read(a.join("keys/platform.key")).unwrap();
    for secret in [&platform[..], b"acme", b"PRIVATE KEY"] {
        assert!(!backup.windows(secret.len()).any(|w| w == secret));
    }
    // Not while it runs.
    refused(
        torngatd(&["new-recovery-code"], &a, ""),
        "is torngatd running?",
    );
    let old_token = r.token.clone();
    drop(r);

    let args = [
        "restore",
        "--backup",
        file.to_str().unwrap(),
        "--tpm-device",
        "none",
        "--allow-unsealed-root",
    ];
    let b = dir.path().join("b");
    let mut mistyped = first.clone().into_bytes();
    mistyped[0] = if mistyped[0] == b'A' { b'B' } else { b'A' };
    let mistyped = String::from_utf8(mistyped).unwrap();
    refused(
        torngatd(&args, &b, &format!("{mistyped}\nyes\n")),
        "mistyped",
    );
    refused(
        torngatd(&args, &b, &format!("{first}\nno\n")),
        "not restored",
    );
    refused(torngatd(&args, &b, &format!("{first}\n")), "not restored");
    refused(
        torngatd(&args, &a, &format!("{first}\nyes\n")),
        "already holds",
    );
    assert!(!b.exists());

    ok(torngatd(
        &args,
        &b,
        &format!("{}\nyes\n", first.to_lowercase()),
    ));
    refused(
        torngatd(&args, &b, &format!("{first}\nyes\n")),
        "already holds",
    );
    assert_eq!(
        std::fs::read(b.join("keys/platform.key")).unwrap(),
        platform
    );
    let same = |f: &str| std::fs::read(a.join(f)).unwrap() == std::fs::read(b.join(f)).unwrap();
    assert!(same("pki/ca.pem") && same("pki/ca.key"));
    assert!(!same("identity/node.key") && !same("admin-token"));

    let r = run(&b);
    // Not just the record from the backup: the node connected with its new identity.
    let end = Instant::now() + Duration::from_secs(30);
    while r.registered() == registered {
        assert!(Instant::now() < end, "n1 never registered again");
        std::thread::sleep(Duration::from_millis(100));
    }
    let strip = |s: &str| {
        let mut v: serde_json::Value = serde_json::from_str(s).unwrap();
        for x in v
            .as_object_mut()
            .unwrap()
            .values_mut()
            .find_map(|x| x.as_array_mut())
            .unwrap()
        {
            // Revisions start again.
            x["metadata"].as_object_mut().unwrap().remove("etag");
        }
        v
    };
    assert!(r.registered().is_string());
    assert_eq!(strip(&r.get(VOLUMES)), strip(&volumes));
    assert!(!r.get(TOKENS).contains("created by init"));
    assert_eq!(r.send(&old_token, "GET", TOKENS, "").0, 401);
    // Backups of the restored cluster open with the same code.
    let again = dir.path().join("again");
    std::fs::write(&again, r.backup()).unwrap();
    drop(r);
    let args = [
        "restore",
        "--backup",
        again.to_str().unwrap(),
        "--tpm-device",
        "none",
        "--allow-unsealed-root",
    ];
    ok(torngatd(
        &args,
        &dir.path().join("c"),
        &format!("{first}\nyes\n"),
    ));

    // A new code opens later backups only.
    let second = code(&ok(torngatd(&["new-recovery-code"], &b, "")));
    let r = run(&b);
    std::fs::write(&again, r.backup()).unwrap();
    drop(r);
    let d = dir.path().join("d");
    refused(
        torngatd(&args, &d, &format!("{first}\nyes\n")),
        "wrong recovery code",
    );
    ok(torngatd(&args, &d, &format!("{second}\nyes\n")));
}
