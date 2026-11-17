//! Deterministic offline fixture generator used by `scripts/check` to exercise `sctl` + `s-vsockd`
//! end-to-end when no physical YubiKey is attached to CI.

use s_proto::{
    enc,
    noise::keypair,
    testkit::{synthetic_signed_macho, MockFidoKey},
};
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            // sk_fixture keygen <seed_byte_hex> <pub_out>
            let seed_byte = enc::unhex(&args[2]).expect("hex")[0];
            let k = MockFidoKey::from_seed([seed_byte; 32], "ci-fido@stone");
            fs::write(&args[3], format!("{}\n", k.pinned().to_authorized_line())).unwrap();
        }
        Some("sign") => {
            // sk_fixture sign <seed_byte_hex> <namespace> <flags_u8> <msg_file> <sig_out>
            let seed_byte = enc::unhex(&args[2]).expect("hex")[0];
            let flags: u8 = args[4].parse().expect("flags");
            let msg = fs::read(&args[5]).expect("msg");
            let k = MockFidoKey::from_seed([seed_byte; 32], "ci-fido@stone");
            let sig = k.sign_sshsig(&args[3], &msg, flags, 1);
            fs::write(&args[6], sig).unwrap();
        }
        Some("macho") => {
            // sk_fixture macho <identifier> <team_id> <out_bin>
            let (bytes, sha, cdhash) =
                synthetic_signed_macho(&args[2], &args[3], b"stone-cleanroom-macho-payload");
            fs::write(&args[4], bytes).unwrap();
            println!("{sha} {cdhash}");
        }
        Some("noise-keys") => {
            // sk_fixture noise-keys <priv_hex_out> <pub_hex_out>
            let kp = keypair().unwrap();
            fs::write(&args[2], format!("{}\n", enc::hex(&kp.private))).unwrap();
            fs::write(&args[3], format!("{}\n", enc::hex(&kp.public))).unwrap();
        }
        _ => {
            eprintln!("usage: sk_fixture <keygen|sign|macho|noise-keys> ...");
            process::exit(2);
        }
    }
}
