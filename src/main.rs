extern crate docopt;
use docopt::Docopt;
const USAGE: &'static str = "
Usage:
  repeated_sd_writes writer [-s <SD_count>] [-p <period>] [-o | -d <duration>] [-c]
  repeated_sd_writes reader [-s <SD_count>] [-p <period>] [-o]
  repeated_sd_writes (-h | --help)

Options:
  -h --help         Show this screen
  -s=<SD_count>     Number of SD to create [default: 49]
  -o                Do it only once
  -p=<period>       Initial delay in seconds [default: 300]
  -d=<duration>     Slow down duration [default: 3600]
  -c                Create account
";

#[macro_use]
extern crate log;
extern crate safe_core;
extern crate self_encryption;
extern crate routing;
extern crate sodiumoxide;
extern crate xor_name;
extern crate maidsafe_utilities;
extern crate rand;

use safe_core::*;
use routing::{Data, DataRequest};
use xor_name::XorName;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::io::{self, Write};
use std::str::FromStr;
use std::thread;

fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    use rand::{self, Rng};
    rand::thread_rng().gen_iter().take(size).collect()
}

fn wait(delay: f64, i: usize, display: bool) {
    let secs = delay.trunc() as u64;
    let nanos = (delay.fract() * 1_000_000_000f64) as u32;
    if display {
        debug!("SD {:2}: next update in secs: {}, nanos: {}", i, secs, nanos);
    }
    std::thread::sleep(std::time::Duration::new(secs, nanos));
}

fn main() {
    let _ = maidsafe_utilities::log::init(false).unwrap();
    let args = Docopt::new(USAGE).and_then(|d| d.parse()).unwrap_or_else(|e| e.exit());
    let sd_count = usize::from_str(args.get_str("-s")).unwrap_or_else(|e| {
                write!(&mut io::stderr(), "Invalid SD count: {}\n", e).unwrap();
                std::process::exit(1)
            });
    let mut period = usize::from_str(args.get_str("-p")).unwrap_or_else(|e| {
                write!(&mut io::stderr(), "Invalid initial period: {}\n", e).unwrap();
                std::process::exit(1)
            }) as f64;
    // Interval initial entre 2 SDs successifs
    let interval_delay = period / sd_count as f64;
    let slow_down_duration = usize::from_str(args.get_str("-d")).unwrap_or_else(|e| {
                write!(&mut io::stderr(), "Invalid slow down duration: {}\n", e).unwrap();
                std::process::exit(1)
            }) as f64;
    let reader_flag = args.get_bool("reader");
    let do_it_once = args.get_bool("-o");
    let new_account = args.get_bool("-c");
    let keyword = "Your Keyword".to_string();
    let pin = "Your Pin".to_string();
    let password = "Your Password".to_string();
    if new_account {
        let _ = core::client::Client::create_account(keyword.clone(), pin.clone(), password.clone()).ok().expect("failed to create account");
        info!("account created");
    }
    let client = core::client::Client::log_in(keyword, pin, password).ok().expect("failed to log_in account");
    info!("account logged-in");
    let client = Arc::new(Mutex::new(client));
    info!("client created");
    thread::sleep(std::time::Duration::from_millis(5_000));

    let type_tag = core::CLIENT_STRUCTURED_DATA_TAG + 689_563_457_681;
    let owner_keys = vec![client.lock().unwrap().get_public_signing_key().unwrap().clone()];
    let prev_owner_keys = Vec::new();
    let space_for_data = core::structured_data_operations::get_approximate_space_for_data(owner_keys.clone(), prev_owner_keys.clone()).unwrap()
        // Margin for imprecision
        - 500;
    info!("Space for data: {}", space_for_data);
    let signing_key = client.lock().unwrap().get_secret_signing_key().unwrap().clone();
    // u0 = p, u1 = p + p - d = u0 + p - d, u2 = p + p - d + p - 2d = u1 + p - 2d, ... un = un-1 + p - n d
    // Let vn = n d
    // u0 = p = p - v0, u1 = 2p - d = 2p - (v0 + v1), u2 = 3p - 3d = 3p - (v0 + v1 + v2), ... un = (n + 1) p - (v0 + v1 + ... vn)
    // vn is an arithmetic progression with common difference d and initial term 0 => v0 + v1 + ... vn = d n (n + 1) / 2
    // => un = (n + 1) p - d n (n + 1) / 2 = (n + 1) (p - n d / 2)
    // s = un and p = n d
    // => s = (p / d + 1) (p - p / 2) = (p + d) / d x p / 2
    // => 2 s d = (p + d) p = p^2 + d p
    // => (2 s - p) d = p^2
    // d = p^2 / (2s - p)
    let denum = 2f64 * slow_down_duration - period;
    if denum <= 0f64 {
        write!(&mut io::stderr(), "Slow down duration should be larger than half the period\n").unwrap();
        std::process::exit(1)
    }
    let decrement: f64 = if reader_flag || do_it_once {0f64} else {period.powi(2) / denum};
    info!("Decrement: {}", decrement);

    // Compte des SD dont la version reste à obtenir. On ne lance pas le traitement tant qu'elles n'ont pas toutes été obtenues.
    // Si le compte viens d'être créé, on les considère toutes obtenues (puisque la version vaut forcément 0)
    let atomic_count = Arc::new(AtomicUsize::new(if new_account {0} else {sd_count}));

    let handles: Vec<_> = (0..sd_count).map(|i| {
        let client = client.clone();
        let owner_keys = owner_keys.clone();
        let prev_owner_keys = prev_owner_keys.clone();
        let signing_key = signing_key.clone();
        let atomic_count = atomic_count.clone();
        thread::spawn(move|| {
            let name: String = format!("Your SD Name {}", i);
            let name = XorName::new(sodiumoxide::crypto::hash::sha512::hash(&name.into_bytes()).0);
            let mut version: u64 = 0;
            let mut known_version = new_account;
            wait(interval_delay * i as f64, i, true);
            loop {
                // Si le compte existe déjà on récupère l'éventuel SD existant
                if !known_version || reader_flag {
                    let request = DataRequest::Structured(name, type_tag);
                    let response_getter = client.lock().unwrap().get(request, None).unwrap();
                    if let Ok(Data::Structured(sd)) = response_getter.get() {
                        version = sd.get_version() + 1;   // On continue la séquence des numéros de version
                    }
                    atomic_count.fetch_sub(1, Ordering::Relaxed);
                    known_version = true;
                    debug!("SD {:2}: next version to write: {}", i, version);
                    if reader_flag && do_it_once {
                        break;
                    }
                }
                if !reader_flag && atomic_count.load(Ordering::Relaxed) == 0 {
                    let data = generate_random_vec_u8(space_for_data);
                    let sd = core::structured_data_operations::unversioned::create(client.clone(),
                        type_tag,
                        name,
                        version,
                        data,
                        owner_keys.clone(),
                        prev_owner_keys.clone(),
                        &signing_key,
                        None).unwrap();     // Encryption Keys
                    let wrapped_sd = Data::Structured(sd);
                    if version == 0 {
                        // Le SD n'existe pas => PUT
                        let _ = client.lock().unwrap().put(wrapped_sd, None).unwrap();
                    } else {
                        // Le SD existe déjà => POST
                        let _ = client.lock().unwrap().post(wrapped_sd, None).unwrap();
                    }
                    debug!("SD {:2}: written version: {}", i, version);
                    if do_it_once {
                        break;
                    }
                    version = version + 1;
                    period -= decrement;
                }
                if period > 0f64 {
                    wait(period, i, atomic_count.load(Ordering::Relaxed) == 0);
                }
                else {
                    break;
                }
            };
        })
    }).collect();

    for h in handles {
        h.join().unwrap();
    }
}
