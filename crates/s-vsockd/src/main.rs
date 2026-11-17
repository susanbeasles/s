use s_proto::{
    enc,
    msg::DEFAULT_VSOCK_PORT,
    noise::Channel,
    sshsig::parse_allowlist,
};
use s_vsockd::{
    transport::bind_unix,
    Engine, Volumes,
};
use std::{env, fs, path::PathBuf, process};

fn usage() -> ! {
    eprintln!(
        "usage: s-vsockd \
         --master <dir> --ledger <dir> --live <dir> \
         --allowlist <sk_authorized_keys> \
         --server-key <hex_priv_file> --client-pub <hex_pub_file> \
         (--vsock-port <port> | --unix <socket_path>) [--once]"
    );
    process::exit(2);
}

fn read_key32(path: &str) -> [u8; 32] {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("s-vsockd: read {path}: {e}");
        process::exit(2);
    });
    enc::unhex32(raw.trim()).unwrap_or_else(|| {
        eprintln!("s-vsockd: {path} must contain 64 lowercase hex chars");
        process::exit(2);
    })
}

fn main() {
    let mut master = None;
    let mut ledger = None;
    let mut live = None;
    let mut allow_path = None;
    let mut server_key_path = None;
    let mut client_pub_path = None;
    let mut vsock_port: Option<u32> = None;
    let mut unix_sock: Option<PathBuf> = None;
    let mut max_conns: Option<usize> = None;

    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--master" => master = args.next().map(PathBuf::from),
            "--ledger" => ledger = args.next().map(PathBuf::from),
            "--live" => live = args.next().map(PathBuf::from),
            "--allowlist" => allow_path = args.next(),
            "--server-key" => server_key_path = args.next(),
            "--client-pub" => client_pub_path = args.next(),
            "--vsock-port" => {
                vsock_port = Some(args.next().unwrap_or_else(|| DEFAULT_VSOCK_PORT.to_string()).parse().unwrap_or_else(|_| usage()))
            }
            "--unix" => unix_sock = args.next().map(PathBuf::from),
            "--once" => max_conns = Some(1),
            "--max-conns" => {
                max_conns = Some(args.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage()))
            }
            _ => usage(),
        }
    }

    let volumes = Volumes {
        master_dir: master.unwrap_or_else(|| usage()),
        ledger_dir: ledger.unwrap_or_else(|| usage()),
        live_dir: live.unwrap_or_else(|| usage()),
    };
    let allow_text = fs::read_to_string(allow_path.unwrap_or_else(|| usage())).unwrap_or_else(|e| {
        eprintln!("s-vsockd: read allowlist: {e}");
        process::exit(2);
    });
    let allowlist = parse_allowlist(&allow_text).unwrap_or_else(|e| {
        eprintln!("s-vsockd: parse allowlist: {e}");
        process::exit(2);
    });
    let server_priv = read_key32(&server_key_path.unwrap_or_else(|| usage()));
    let client_pub = read_key32(&client_pub_path.unwrap_or_else(|| usage()));

    let mut engine = Engine::open(volumes, allowlist).unwrap_or_else(|e| {
        eprintln!("s-vsockd: init failed: {e}");
        process::exit(1);
    });

    if let Some(sock_path) = unix_sock {
        let listener = bind_unix(&sock_path).unwrap_or_else(|e| {
            eprintln!("s-vsockd: bind {}: {e}", sock_path.display());
            process::exit(1);
        });
        let mut served = 0usize;
        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    if let Ok(ch) = Channel::accept(stream, &server_priv, &[client_pub]) {
                        let _ = engine.serve_channel(ch);
                    }
                    served += 1;
                    if max_conns.is_some_and(|m| served >= m) {
                        break;
                    }
                }
                Err(e) => eprintln!("s-vsockd: accept: {e}"),
            }
        }
        let _ = fs::remove_file(&sock_path);
        return;
    }

    #[cfg(target_os = "linux")]
    if let Some(port) = vsock_port {
        let listener =
            s_vsockd::transport::VsockListener::bind(libc::VMADDR_CID_ANY, port).unwrap_or_else(
                |e| {
                    eprintln!("s-vsockd: bind AF_VSOCK port {port}: {e}");
                    process::exit(1);
                },
            );
        let mut served = 0usize;
        loop {
            match listener.accept() {
                Ok(stream) => {
                    if let Ok(ch) = Channel::accept(stream, &server_priv, &[client_pub]) {
                        let _ = engine.serve_channel(ch);
                    }
                    served += 1;
                    if max_conns.is_some_and(|m| served >= m) {
                        break;
                    }
                }
                Err(e) => eprintln!("s-vsockd: vsock accept: {e}"),
            }
        }
    } else {
        usage();
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = vsock_port;
        usage();
    }
}
