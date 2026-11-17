use s_proto::sshsig::{parse_allowlist, verify};
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: sshsig_verify <allowlist> <namespace> <message_file> <sig_file>");
        process::exit(2);
    }
    let allow = parse_allowlist(&fs::read_to_string(&args[1]).expect("read allowlist"))
        .expect("parse allowlist");
    let msg = fs::read(&args[3]).expect("read message");
    let sig = fs::read_to_string(&args[4]).expect("read sig");
    match verify(&sig, &args[2], &msg, &allow) {
        Ok(v) => {
            println!(
                "OK fp={} flags=0x{:02x} counter={}",
                v.key_fingerprint_sha256, v.flags, v.counter
            );
        }
        Err(e) => {
            eprintln!("REJECT: {e}");
            process::exit(1);
        }
    }
}
