use chronohash::{ChronoHash, Mode};
use std::env;
use std::fs;
use std::io::{self, Read};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let mut mode = Mode::Normal;
    let mut input = String::new();
    let mut from_file = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--fast" | "-f" => mode = Mode::Fast,
            "--normal" | "-n" => mode = Mode::Normal,
            "--file" => {
                if i + 1 < args.len() {
                    from_file = true;
                    input = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("Error: --file requires a filename");
                    return;
                }
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" | "-v" => {
                println!("ChronoHash v1.2.0");
                return;
            }
            arg if !arg.starts_with('-') => {
                input = arg.to_string();
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                print_usage();
                return;
            }
        }
        i += 1;
    }

    let hasher = ChronoHash::new(mode);

    if from_file {
        // Hash file contents
        match fs::read(&input) {
            Ok(data) => {
                let hash = hasher.hash(&data);
                println!("{}", hex_encode(&hash));
            }
            Err(e) => {
                eprintln!("Error reading file '{}': {}", input, e);
                std::process::exit(1);
            }
        }
    } else if input.is_empty() {
        // Read from stdin
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer).expect("Failed to read from stdin");
        let hash = hasher.hash(&buffer);
        println!("{}", hex_encode(&hash));
    } else {
        // Hash string
        let hash = hasher.hash(input.as_bytes());
        println!("{}", hex_encode(&hash));
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn print_usage() {
    println!("Usage: chronohash-cli [OPTIONS] [INPUT]");
    println!("Try 'chronohash-cli --help' for more information.");
}

fn print_help() {
    println!("ChronoHash CLI - A novel cryptographic hash function");
    println!();
    println!("USAGE:");
    println!("    chronohash-cli [OPTIONS] [INPUT]");
    println!();
    println!("OPTIONS:");
    println!("    -f, --fast          Use fast mode (8 rounds, ~1M+ h/s)");
    println!("    -n, --normal        Use normal mode (20-32 rounds, maximum security) [default]");
    println!("    --file <FILE>       Hash contents of FILE");
    println!("    -h, --help          Print help information");
    println!("    -v, --version       Print version information");
    println!();
    println!("EXAMPLES:");
    println!("    chronohash-cli \"Hello, World!\"");
    println!("    chronohash-cli --fast \"Hello, World!\"");
    println!("    chronohash-cli --file input.txt");
    println!("    echo \"Hello\" | chronohash-cli");
    println!();
    println!("MODES:");
    println!("    Normal Mode: 20-32 dynamic rounds based on input complexity");
    println!("                 Maximum security with temporal diffusion");
    println!("    Fast Mode:   8 fixed rounds with optimized operations");
    println!("                 ~1M+ hashes/second, excellent for performance");
}
