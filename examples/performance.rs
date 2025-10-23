use chronohash::{ChronoHash, Mode};
use std::time::Instant;

fn main() {
    println!("ChronoHash Rust Performance Test");
    println!("==================================\n");

    let test_data = b"0123456789";
    let iterations = 1_000_000;

    // Fast mode
    let hasher = ChronoHash::new(Mode::Fast);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hasher.hash(test_data);
    }
    let elapsed = start.elapsed();
    let rate_fast = iterations as f64 / elapsed.as_secs_f64();

    println!("Fast Mode (10 bytes, {} iterations):", iterations);
    println!("  Time:  {:.3}s", elapsed.as_secs_f64());
    println!("  Rate:  {:.0} hashes/second", rate_fast);
    println!("  Per hash: {:.2} μs\n", elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64);

    // Normal mode
    let hasher = ChronoHash::new(Mode::Normal);
    let iterations_normal = 100_000;
    let start = Instant::now();
    for _ in 0..iterations_normal {
        let _ = hasher.hash(test_data);
    }
    let elapsed = start.elapsed();
    let rate_normal = iterations_normal as f64 / elapsed.as_secs_f64();

    println!("Normal Mode (10 bytes, {} iterations):", iterations_normal);
    println!("  Time:  {:.3}s", elapsed.as_secs_f64());
    println!("  Rate:  {:.0} hashes/second", rate_normal);
    println!("  Per hash: {:.2} μs\n", elapsed.as_secs_f64() * 1_000_000.0 / iterations_normal as f64);

    println!("Speedup: Fast mode is {:.1}x faster than Normal mode", rate_fast / rate_normal);
    
    if rate_fast >= 1_000_000.0 {
        println!("\n✅ TARGET ACHIEVED: {:.0} h/s >= 1,000,000 h/s!", rate_fast);
    } else {
        println!("\n📊 Progress: {:.0} h/s ({:.1}% of 1M target)", rate_fast, rate_fast / 10_000.0);
    }
    
    // Sample hash
    let hash = hasher.hash_hex(b"Hello, World!");
    println!("\nSample hash (Normal mode): {}", hash);
}
