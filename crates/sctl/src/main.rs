//! `sctl` - host operator CLI speaking the 5-verb `Noise_IK` contract to `s-vsockd`
//! (either directly over `AF_VSOCK` or through `SVMHost`'s local `VZVirtioSocketDevice` relay).

use s_ledger::Ledger;
use s_proto::{
    client::Client,
    enc,
    macho::verify_macho_cdhash,
    msg::{
        ChallengePolicyReq, CommitPolicyReq, IngestBundleReq, Lineup, PolicyAction, PolicyProposal,
        DEFAULT_VSOCK_CID, DEFAULT_VSOCK_PORT,
    },
    noise::Channel,
    sshsig::{parse_allowlist, POLICY_NAMESPACE},
    tree::digest_dir,
};
use std::{
    env, fs,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
};

struct ConnOpts {
    unix: Option<PathBuf>,
    vsock: (u32, u32),
    host_key: PathBuf,
    guest_pub: PathBuf,
}

enum Endpoint {
    Unix(UnixStream),
    #[cfg(target_os = "linux")]
    Vsock(std::os::fd::OwnedFd),
}

impl Read for Endpoint {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.read(buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(fd) => {
                use std::os::fd::AsRawFd;
                let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            }
        }
    }
}

impl Write for Endpoint {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.write(buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(fd) => {
                use std::os::fd::AsRawFd;
                let n = unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn connect(opts: &ConnOpts) -> Client<Endpoint> {
    let host_priv = read_key32(&opts.host_key);
    let guest_pub = read_key32(&opts.guest_pub);
    let ep = if let Some(u) = &opts.unix {
        Endpoint::Unix(UnixStream::connect(u).unwrap_or_else(|e| die(&format!("connect {}: {e}", u.display()))))
    } else {
        connect_vsock(opts.vsock.0, opts.vsock.1)
    };
    let ch = Channel::connect(ep, &host_priv, &guest_pub)
        .unwrap_or_else(|e| die(&format!("Noise_IK handshake failed: {e}")));
    Client::new(ch)
}

#[cfg(target_os = "linux")]
fn connect_vsock(cid: u32, port: u32) -> Endpoint {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        die(&format!("AF_VSOCK socket: {}", io::Error::last_os_error()));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;
    let rc = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        die(&format!("AF_VSOCK connect cid={cid} port={port}: {}", io::Error::last_os_error()));
    }
    Endpoint::Vsock(owned)
}

#[cfg(not(target_os = "linux"))]
fn connect_vsock(_cid: u32, _port: u32) -> Endpoint {
    die("on macOS pass --socket /var/run/s/vsock.sock exposed by SVMHost VZVirtioSocketDevice")
}

fn read_key32(p: &Path) -> [u8; 32] {
    let raw = fs::read_to_string(p).unwrap_or_else(|e| die(&format!("read {}: {e}", p.display())));
    enc::unhex32(raw.trim()).unwrap_or_else(|| die(&format!("{}: expected 64 hex chars", p.display())))
}

fn die(msg: &str) -> ! {
    eprintln!("sctl: {msg}");
    process::exit(1);
}

fn usage() -> ! {
    eprintln!(
        "usage: sctl [connection flags] <subcommand>\n\
         connection flags:\n  \
           --socket <unix_sock>       Connect via SVMHost VZVirtioSocket relay\n  \
           --vsock <cid>:<port>       Connect directly via AF_VSOCK (default 3:7001)\n  \
           --host-key <hex_file>      Host Noise_IK static private key\n  \
           --guest-pub <hex_file>     Pinned guest s-vsockd Noise_IK static public key\n\
         subcommands:\n  \
           status\n  \
           verify [--host-root <dir>]\n  \
           ingest --bundle <name> --version <ver> --bin <macho> --team-id <TEAM> --sig <sshsig>\n  \
           policy plan <lineup.json>\n  \
           policy challenge (--enforce <lineup.json> | --suspend | --rollback <gen>) [--signable-out <file>]\n  \
           policy commit --nonce <hex> --sig <sshsig_file>\n  \
           policy apply <lineup.json> --ssh-key <sk_key_file>\n  \
           policy rollback <gen> --ssh-key <sk_key_file>\n  \
           ledger verify --dir <ledger_dir> [--allowlist <sk_authorized_keys>]\n  \
           ledger inspect --dir <ledger_dir> [--cdhash <hex>]"
    );
    process::exit(2);
}

fn sign_with_ssh_keygen(sk_key_path: &Path, message: &[u8]) -> String {
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-q", "-n", POLICY_NAMESPACE, "-f"])
        .arg(sk_key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| die(&format!("spawn ssh-keygen -Y sign: {e}")));
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(message)
        .unwrap_or_else(|e| die(&format!("write challenge to ssh-keygen: {e}")));
    let out = child.wait_with_output().unwrap_or_else(|e| die(&format!("wait ssh-keygen: {e}")));
    if !out.status.success() {
        die(&format!("ssh-keygen -Y sign failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    String::from_utf8(out.stdout).unwrap_or_else(|_| die("non-utf8 ssh-keygen signature"))
}

fn load_lineup(path: &str) -> Lineup {
    let text = fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
    let lineup: Lineup =
        serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("parse {path}: {e}")));
    lineup.validate().unwrap_or_else(|e| die(&format!("invalid lineup: {e}")));
    lineup
}

fn print_json<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

fn main() {
    let mut unix = env::var_os("S_SOCKET").map(PathBuf::from);
    let mut vsock = (DEFAULT_VSOCK_CID, DEFAULT_VSOCK_PORT);
    let mut host_key = env::var_os("S_HOST_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/s/host_noise.key"));
    let mut guest_pub = env::var_os("S_GUEST_PUB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/s/guest_noise.pub"));

    let mut rest = Vec::new();
    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => unix = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--vsock" => {
                let s = it.next().unwrap_or_else(|| usage());
                let (c, p) = s.split_once(':').unwrap_or_else(|| usage());
                vsock = (c.parse().unwrap_or_else(|_| usage()), p.parse().unwrap_or_else(|_| usage()));
            }
            "--host-key" => host_key = PathBuf::from(it.next().unwrap_or_else(|| usage())),
            "--guest-pub" => guest_pub = PathBuf::from(it.next().unwrap_or_else(|| usage())),
            "--help" | "-h" => usage(),
            other => {
                rest.push(other.to_owned());
                rest.extend(it);
                break;
            }
        }
    }

    let opts = ConnOpts { unix, vsock, host_key, guest_pub };
    match rest.first().map(String::as_str) {
        Some("status") => {
            let mut c = connect(&opts);
            let st = c.status().unwrap_or_else(|e| die(&e.to_string()));
            print_json(&st);
        }
        Some("verify") => {
            let mut host_root: Option<PathBuf> = None;
            let mut i = 1;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--host-root" => {
                        host_root = Some(PathBuf::from(rest.get(i + 1).unwrap_or_else(|| usage())));
                        i += 2;
                    }
                    _ => usage(),
                }
            }
            let obs = host_root.map(|r| {
                digest_dir(&r)
                    .unwrap_or_else(|e| die(&format!("digest {}: {e}", r.display())))
                    .0
            });
            let mut c = connect(&opts);
            let vf = c.verify(obs).unwrap_or_else(|e| die(&e.to_string()));
            print_json(&vf);
            if !vf.verified {
                process::exit(1);
            }
        }
        Some("ingest") => {
            let mut bundle = None;
            let mut version = None;
            let mut bin_path = None;
            let mut team_id = None;
            let mut sig_path = None;
            let mut i = 1;
            while i < rest.len() {
                let val = rest.get(i + 1).unwrap_or_else(|| usage()).clone();
                match rest[i].as_str() {
                    "--bundle" => bundle = Some(val),
                    "--version" => version = Some(val),
                    "--bin" => bin_path = Some(PathBuf::from(val)),
                    "--team-id" => team_id = Some(val),
                    "--sig" => sig_path = Some(PathBuf::from(val)),
                    _ => usage(),
                }
                i += 2;
            }
            let bin_bytes = fs::read(bin_path.unwrap_or_else(|| usage()))
                .unwrap_or_else(|e| die(&format!("read binary: {e}")));
            let sha = enc::hex(&enc::sha256(&bin_bytes));
            let macho = verify_macho_cdhash(&bin_bytes)
                .unwrap_or_else(|e| die(&format!("local Mach-O check failed: {e}")));
            let sig = fs::read_to_string(sig_path.unwrap_or_else(|| usage()))
                .unwrap_or_else(|e| die(&format!("read detached sig: {e}")));
            let mut c = connect(&opts);
            let resp = c
                .ingest_bundle(IngestBundleReq {
                    bundle_name: bundle.unwrap_or_else(|| usage()),
                    version: version.unwrap_or_else(|| usage()),
                    binary_b64: Some(enc::b64(&bin_bytes)),
                    quarantine_rel_path: None,
                    expected_sha256: sha,
                    expected_cdhash: macho.cdhash,
                    expected_team_id: team_id.unwrap_or_else(|| usage()),
                    detached_sshsig: sig,
                })
                .unwrap_or_else(|e| die(&e.to_string()));
            print_json(&resp);
        }
        Some("policy") => handle_policy(&opts, &rest[1..]),
        Some("ledger") => handle_ledger(&rest[1..]),
        _ => usage(),
    }
}

fn handle_policy(opts: &ConnOpts, args: &[String]) {
    match args.first().map(String::as_str) {
        Some("plan") => {
            let lineup = load_lineup(args.get(1).unwrap_or_else(|| usage()));
            let prop = PolicyProposal {
                action: PolicyAction::Enforce,
                lineup: Some(lineup),
                rollback_generation: None,
            };
            let sha = prop.sha256_hex().unwrap_or_else(|e| die(&e.to_string()));
            print_json(&serde_json::json!({
                "valid": true,
                "proposedPolicySha256": sha,
                "entryCount": prop.lineup.as_ref().unwrap().entries.len(),
            }));
        }
        Some("challenge") => {
            let mut action = None;
            let mut lineup = None;
            let mut rb_gen = None;
            let mut signable_out: Option<PathBuf> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--enforce" => {
                        action = Some(PolicyAction::Enforce);
                        lineup = Some(load_lineup(args.get(i + 1).unwrap_or_else(|| usage())));
                        i += 2;
                    }
                    "--suspend" => {
                        action = Some(PolicyAction::Suspend);
                        i += 1;
                    }
                    "--rollback" => {
                        action = Some(PolicyAction::Rollback);
                        rb_gen = Some(
                            args.get(i + 1)
                                .unwrap_or_else(|| usage())
                                .parse()
                                .unwrap_or_else(|_| usage()),
                        );
                        i += 2;
                    }
                    "--signable-out" => {
                        signable_out = Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| usage())));
                        i += 2;
                    }
                    _ => usage(),
                }
            }
            let mut c = connect(opts);
            let ch = c
                .challenge_policy(ChallengePolicyReq {
                    action: action.unwrap_or_else(|| usage()),
                    lineup,
                    rollback_generation: rb_gen,
                })
                .unwrap_or_else(|e| die(&e.to_string()));
            if let Some(out) = signable_out {
                let bytes = ch.signable().canonical_bytes().unwrap_or_else(|e| die(&e.to_string()));
                fs::write(out, bytes).unwrap_or_else(|e| die(&format!("write signable: {e}")));
            }
            print_json(&ch);
        }
        Some("commit") => {
            let mut nonce = None;
            let mut sig_file = None;
            let mut i = 1;
            while i < args.len() {
                let val = args.get(i + 1).unwrap_or_else(|| usage()).clone();
                match args[i].as_str() {
                    "--nonce" => nonce = Some(val),
                    "--sig" => sig_file = Some(PathBuf::from(val)),
                    _ => usage(),
                }
                i += 2;
            }
            let sig = fs::read_to_string(sig_file.unwrap_or_else(|| usage()))
                .unwrap_or_else(|e| die(&format!("read sig: {e}")));
            let mut c = connect(opts);
            let resp = c
                .commit_policy(CommitPolicyReq {
                    challenge_nonce: nonce.unwrap_or_else(|| usage()),
                    fido_ssh_sig: sig,
                })
                .unwrap_or_else(|e| die(&e.to_string()));
            print_json(&resp);
        }
        Some("apply") => {
            let lineup = load_lineup(args.get(1).unwrap_or_else(|| usage()));
            let key_path = parse_ssh_key_flag(&args[2..]);
            let mut c = connect(opts);
            let ch = c
                .challenge_policy(ChallengePolicyReq {
                    action: PolicyAction::Enforce,
                    lineup: Some(lineup),
                    rollback_generation: None,
                })
                .unwrap_or_else(|e| die(&e.to_string()));
            let signable = ch.signable().canonical_bytes().unwrap_or_else(|e| die(&e.to_string()));
            let sig = sign_with_ssh_keygen(&key_path, &signable);
            let resp = c
                .commit_policy(CommitPolicyReq { challenge_nonce: ch.nonce, fido_ssh_sig: sig })
                .unwrap_or_else(|e| die(&e.to_string()));
            print_json(&resp);
        }
        Some("rollback") => {
            let gen: u64 = args
                .get(1)
                .unwrap_or_else(|| usage())
                .parse()
                .unwrap_or_else(|_| usage());
            let key_path = parse_ssh_key_flag(&args[2..]);
            let mut c = connect(opts);
            let ch = c
                .challenge_policy(ChallengePolicyReq {
                    action: PolicyAction::Rollback,
                    lineup: None,
                    rollback_generation: Some(gen),
                })
                .unwrap_or_else(|e| die(&e.to_string()));
            let signable = ch.signable().canonical_bytes().unwrap_or_else(|e| die(&e.to_string()));
            let sig = sign_with_ssh_keygen(&key_path, &signable);
            let resp = c
                .commit_policy(CommitPolicyReq { challenge_nonce: ch.nonce, fido_ssh_sig: sig })
                .unwrap_or_else(|e| die(&e.to_string()));
            print_json(&resp);
        }
        _ => usage(),
    }
}

fn parse_ssh_key_flag(args: &[String]) -> PathBuf {
    if args.len() == 2 && args[0] == "--ssh-key" {
        PathBuf::from(&args[1])
    } else {
        usage()
    }
}

fn handle_ledger(args: &[String]) {
    match args.first().map(String::as_str) {
        Some("verify") => {
            let mut dir = None;
            let mut allow = None;
            let mut i = 1;
            while i < args.len() {
                let val = args.get(i + 1).unwrap_or_else(|| usage()).clone();
                match args[i].as_str() {
                    "--dir" => dir = Some(PathBuf::from(val)),
                    "--allowlist" => allow = Some(PathBuf::from(val)),
                    _ => usage(),
                }
                i += 2;
            }
            let keys = allow.map(|p| {
                let t = fs::read_to_string(&p).unwrap_or_else(|e| die(&format!("read allowlist: {e}")));
                parse_allowlist(&t).unwrap_or_else(|e| die(&format!("parse allowlist: {e}")))
            });
            let ledger = Ledger::open(dir.unwrap_or_else(|| usage()), keys.as_deref())
                .unwrap_or_else(|e| die(&format!("ledger verification FAILED: {e}")));
            print_json(&serde_json::json!({
                "verified": true,
                "records": ledger.len(),
                "tipSha256": ledger.tip_sha256(),
            }));
        }
        Some("inspect") => {
            let mut dir = None;
            let mut cdhash = None;
            let mut i = 1;
            while i < args.len() {
                let val = args.get(i + 1).unwrap_or_else(|| usage()).clone();
                match args[i].as_str() {
                    "--dir" => dir = Some(PathBuf::from(val)),
                    "--cdhash" => cdhash = Some(val),
                    _ => usage(),
                }
                i += 2;
            }
            let ledger = Ledger::open(dir.unwrap_or_else(|| usage()), None)
                .unwrap_or_else(|e| die(&e.to_string()));
            if let Some(cd) = cdhash {
                print_json(&serde_json::json!({
                    "cdhash": cd,
                    "seqs": ledger.lookup_cdhash(&cd),
                }));
            } else {
                let summary: Vec<_> = ledger
                    .records()
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "seq": r.record.seq,
                            "sha256": r.record_sha256,
                            "prevSha256": r.record.prev_record_sha256,
                            "generation": r.record.resulting_generation,
                            "state": r.record.state,
                            "liveMountDigest": r.record.live_mount_digest,
                        })
                    })
                    .collect();
                print_json(&summary);
            }
        }
        _ => usage(),
    }
}
