//! A small QMP client (blocking; run it off the async runtime).
//!
//! QEMU runs as the instance's user and may be under its guest's control: everything it answers is
//! untrusted. Lines are bounded, every exchange has a timeout, and the peer must be the process
//! the caller expects.

use std::io::{BufRead, BufReader, IoSlice, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use serde_json::{Value, json};

/// Longest line read from QEMU.
const MAX_LINE: u64 = 64 * 1024;

pub struct Qmp {
    /// Written to through `get_ref`.
    reader: BufReader<UnixStream>,
    deadline: Instant,
}

impl std::fmt::Debug for Qmp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Qmp")
    }
}

fn err(m: impl Into<String>) -> std::io::Error {
    std::io::Error::other(m.into())
}

impl Qmp {
    /// Negotiates on a connected `stream`: each read and write within `io_timeout`, the whole
    /// session within `total`. Nothing is sent unless the other end is process `pid` and not root.
    pub fn new(
        stream: UnixStream,
        pid: i32,
        io_timeout: Duration,
        total: Duration,
    ) -> std::io::Result<Self> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(io_timeout))?;
        stream.set_write_timeout(Some(io_timeout))?;
        let peer = rustix::net::sockopt::socket_peercred(&stream)?;
        if pid <= 0 || peer.pid.as_raw_nonzero().get() != pid || peer.uid.is_root() {
            return Err(err("the QMP socket is not the instance's own"));
        }
        let mut qmp = Self {
            reader: BufReader::new(stream),
            deadline: Instant::now() + total,
        };
        qmp.line()?; // greeting
        qmp.execute("qmp_capabilities", None)?;
        Ok(qmp)
    }

    fn line(&mut self) -> std::io::Result<Value> {
        if Instant::now() >= self.deadline {
            return Err(err("QMP: timed out"));
        }
        let mut buf = Vec::new();
        (&mut self.reader)
            .take(MAX_LINE)
            .read_until(b'\n', &mut buf)?;
        if buf.last() != Some(&b'\n') {
            return Err(err("QMP: connection closed or line too long"));
        }
        serde_json::from_slice(&buf).map_err(|_| err("QMP: not JSON"))
    }

    /// Runs `command` and returns its result; QEMU's error is returned as text.
    pub fn execute(&mut self, command: &str, arguments: Option<Value>) -> std::io::Result<Value> {
        self.send(command, arguments, None)
    }

    /// Like [`execute`](Self::execute), passing `fd` along (SCM_RIGHTS), e.g. for `add-fd`.
    pub fn execute_with_fd(
        &mut self,
        command: &str,
        arguments: Option<Value>,
        fd: BorrowedFd<'_>,
    ) -> std::io::Result<Value> {
        self.send(command, arguments, Some(fd))
    }

    fn send(
        &mut self,
        command: &str,
        arguments: Option<Value>,
        fd: Option<BorrowedFd<'_>>,
    ) -> std::io::Result<Value> {
        let mut msg = match arguments {
            Some(a) => json!({ "execute": command, "arguments": a }),
            None => json!({ "execute": command }),
        }
        .to_string();
        msg.push('\n');
        let mut rest = msg.as_bytes();
        if let Some(fd) = fd {
            let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            let fds = [fd];
            if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
                return Err(err("QMP: cannot pass the descriptor"));
            }
            let sent = rustix::net::sendmsg(
                self.reader.get_ref(),
                &[IoSlice::new(rest)],
                &mut control,
                SendFlags::NOSIGNAL,
            )?;
            rest = &rest[sent..];
        }
        self.reader.get_ref().write_all(rest)?;
        loop {
            let reply = self.line()?;
            // Events can come before the answer.
            if reply.get("event").is_some() {
                continue;
            }
            if let Some(r) = reply.get("return") {
                return Ok(r.clone());
            }
            let desc = reply
                .pointer("/error/desc")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(err(format!("qmp {command}: {desc}")));
        }
    }
}
