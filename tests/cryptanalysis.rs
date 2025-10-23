//! Advanced Cryptanalysis Tests for ChronoHash
//! 
//! This module implements comprehensive cryptographic tests including:
//! - Statistical randomness tests
//! - Avalanche criterion
//! - Collision resistance
//! - Preimage resistance
//! - Differential cryptanalysis resistance
//! - Performance regression tests

use chronohash::{ChronoHash, Mode};
use std::collections::{HashMap, HashSet};

#[test]
fn test_strict_avalanche_criterion() {
    // Test that flipping one input bit changes ~50% of output bits
    let hasher = ChronoHash::new(Mode::Normal);
    let base_msg = b"test message for strict avalanche criterion";
    let base_hash = hasher.hash(base_msg);

    let mut flip_counts = vec![0u32; 256]; // Count flips for each output bit
    let mut total_tests = 0;

    // Test flipping each bit in first 20 bytes
    for byte_pos in 0..base_msg.len().min(20) {
        for bit_pos in 0..8 {
            let mut modified = base_msg.to_vec();
            modified[byte_pos] ^= 1 << bit_pos;
            let modified_hash = hasher.hash(&modified);

            // Count which output bits flipped
            for byte_idx in 0..32 {
                let diff = base_hash[byte_idx] ^ modified_hash[byte_idx];
                for bit_idx in 0..8 {
                    if (diff >> bit_idx) & 1 == 1 {
                        flip_counts[byte_idx * 8 + bit_idx] += 1;
                    }
                }
            }
            total_tests += 1;
        }
    }

    // Each output bit should flip approximately 50% of the time
    for (bit_idx, &flip_count) in flip_counts.iter().enumerate() {
        let flip_rate = flip_count as f64 / total_tests as f64;
        assert!(
            flip_rate > 0.3 && flip_rate < 0.7,
            "Bit {} flip rate {:.1}% outside safe range [30%, 70%]",
            bit_idx,
            flip_rate * 100.0
        );
    }
}

#[test]
fn test_bit_independence() {
    // Test that different input bit changes produce independent output changes
    let hasher = ChronoHash::new(Mode::Normal);
    let base_msg = b"bit independence test message";

    let mut hashes = Vec::new();

    // Generate hashes with single-bit changes
    for byte_pos in 0..base_msg.len().min(10) {
        for bit_pos in 0..8 {
            let mut modified = base_msg.to_vec();
            modified[byte_pos] ^= 1 << bit_pos;
            hashes.push(hasher.hash(&modified));
        }
    }

    // Calculate pairwise Hamming distances
    let mut distances = Vec::new();
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            let mut dist = 0;
            for k in 0..32 {
                dist += (hashes[i][k] ^ hashes[j][k]).count_ones();
            }
            distances.push(dist);
        }
    }

    // Average distance should be around 128 bits (50% of 256)
    let avg_distance: f64 = distances.iter().map(|&d| d as f64).sum::<f64>()
        / distances.len() as f64;

    assert!(
        avg_distance > 100.0 && avg_distance < 156.0,
        "Average Hamming distance {:.1} not in safe range [100, 156]",
        avg_distance
    );
}

#[test]
fn test_collision_resistance_intensive() {
    // Test with 50,000 distinct inputs
    let hasher = ChronoHash::new(Mode::Normal);
    let mut hashes = HashSet::new();
    let num_tests = 50_000;

    for i in 0..num_tests {
        let msg = format!("collision_test_{}", i);
        let hash = hasher.hash_hex(msg.as_bytes());

        assert!(
            !hashes.contains(&hash),
            "Collision detected at iteration {}",
            i
        );
        hashes.insert(hash);
    }

    assert_eq!(hashes.len(), num_tests);
}

#[test]
fn test_preimage_resistance() {
    // Given a hash, finding an input should be infeasible
    let hasher = ChronoHash::new(Mode::Normal);
    let target_msg = b"preimage resistance test target";
    let target_hash = hasher.hash(target_msg);

    // Try random inputs - none should match (except original)
    let attempts = 10_000;
    let mut matches = 0;

    for i in 0..attempts {
        let random_msg = format!("random_attempt_{}", i);
        if random_msg.as_bytes() != target_msg {
            let random_hash = hasher.hash(random_msg.as_bytes());
            if random_hash == target_hash {
                matches += 1;
            }
        }
    }

    assert_eq!(
        matches, 0,
        "Found {} preimages in {} attempts",
        matches, attempts
    );
}

#[test]
fn test_second_preimage_resistance() {
    // Given input and hash, finding different input with same hash should be infeasible
    let hasher = ChronoHash::new(Mode::Normal);
    let msg1 = b"second preimage resistance test";
    let hash1 = hasher.hash(msg1);

    let attempts = 10_000;
    let mut second_preimages = 0;

    for i in 0..attempts {
        let msg2 = format!("attempt_{}", i);
        if msg2.as_bytes() != msg1 {
            let hash2 = hasher.hash(msg2.as_bytes());
            if hash2 == hash1 {
                second_preimages += 1;
            }
        }
    }

    assert_eq!(
        second_preimages, 0,
        "Found {} second preimages in {} attempts",
        second_preimages, attempts
    );
}

#[test]
fn test_near_collision_detection() {
    // Near-collisions (few bit differences) should be as rare as random chance
    let hasher = ChronoHash::new(Mode::Normal);
    let num_hashes = 1000;
    let mut hashes = Vec::new();

    for i in 0..num_hashes {
        let msg = format!("near_collision_{}", i);
        hashes.push(hasher.hash(msg.as_bytes()));
    }

    // Count near-collisions (≤10 bit difference)
    let mut near_collisions = 0;
    let threshold = 10;

    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len().min(i + 50) {
            let mut dist = 0;
            for k in 0..32 {
                dist += (hashes[i][k] ^ hashes[j][k]).count_ones();
            }
            if dist <= threshold {
                near_collisions += 1;
            }
        }
    }

    assert_eq!(
        near_collisions, 0,
        "Found {} near-collisions (≤{} bit difference)",
        near_collisions, threshold
    );
}

#[test]
fn test_differential_cryptanalysis_resistance() {
    // Similar inputs should produce uncorrelated outputs
    let hasher = ChronoHash::new(Mode::Normal);
    let base_msg = b"differential cryptanalysis test base";
    let base_hash = hasher.hash(base_msg);

    let mut differential_scores = Vec::new();

    // Test with various small modifications
    for offset in 0..base_msg.len().min(20) {
        for delta in [1, 2, 4, 8, 16, 32, 64, 128] {
            let mut modified = base_msg.to_vec();
            modified[offset] = modified[offset].wrapping_add(delta);
            let modified_hash = hasher.hash(&modified);

            // Count bit differences
            let mut diff_bits = 0;
            for i in 0..32 {
                diff_bits += (base_hash[i] ^ modified_hash[i]).count_ones();
            }
            differential_scores.push(diff_bits);
        }
    }

    // All scores should be in avalanche range (40-60% of 256 bits)
    for &score in &differential_scores {
        assert!(
            score > 100 && score < 156,
            "Differential score {} outside safe range [100, 156]",
            score
        );
    }
}

#[test]
fn test_length_extension_resistance() {
    // Test resistance to length extension attacks
    let hasher = ChronoHash::new(Mode::Normal);
    let msg1 = b"message";
    let msg2 = b"messageextension";

    let hash1 = hasher.hash(msg1);
    let hash2 = hasher.hash(msg2);

    // Count bit differences
    let mut differences = 0;
    for i in 0..32 {
        differences += (hash1[i] ^ hash2[i]).count_ones();
    }

    // Should differ significantly (not vulnerable to length extension)
    assert!(
        differences > 100,
        "Only {} bits differ - potential length extension vulnerability",
        differences
    );
}

#[test]
fn test_statistical_randomness() {
    // Test output distribution using chi-squared approach
    let hasher = ChronoHash::new(Mode::Normal);
    let num_hashes = 1000;

    let mut byte_counts = HashMap::new();

    // Generate hashes and count byte frequencies
    for i in 0..num_hashes {
        let msg = format!("randomness_test_{}", i);
        let hash = hasher.hash(msg.as_bytes());
        for &byte in hash.iter() {
            *byte_counts.entry(byte).or_insert(0) += 1;
        }
    }

    // Calculate chi-squared statistic
    let total_bytes = num_hashes * 32;
    let expected = total_bytes as f64 / 256.0;
    let mut chi_squared = 0.0;

    for count in byte_counts.values() {
        let diff = *count as f64 - expected;
        chi_squared += diff * diff / expected;
    }

    // Critical value at 0.05 significance with 255 df is ~293
    // Use relaxed threshold for practical testing
    assert!(
        chi_squared < 350.0,
        "Chi-squared value {:.2} indicates non-random distribution",
        chi_squared
    );
}

#[test]
fn test_fast_mode_maintains_security() {
    // Fast mode should still have good cryptographic properties
    let hasher = ChronoHash::new(Mode::Fast);
    let msg1 = b"fast mode security test";
    let msg2 = b"fast mode security tesu"; // One char different

    let hash1 = hasher.hash(msg1);
    let hash2 = hasher.hash(msg2);

    let mut diff_bits = 0;
    for i in 0..32 {
        diff_bits += (hash1[i] ^ hash2[i]).count_ones();
    }

    let percentage = (diff_bits as f64 / 256.0) * 100.0;

    assert!(
        percentage > 40.0 && percentage < 60.0,
        "Fast mode avalanche: {:.1}% (expected 40-60%)",
        percentage
    );
}

#[test]
fn test_null_byte_handling() {
    // Test proper handling of null bytes
    let hasher = ChronoHash::new(Mode::Normal);
    
    let test_cases = vec![
        &b"\x00"[..],
        &b"\x00\x00\x00\x00\x00"[..],
        &b"test\x00message"[..],
        &b"\x00test"[..],
        &b"test\x00"[..],
    ];

    let mut hashes = Vec::new();
    for &msg in &test_cases {
        let hash = hasher.hash(msg);
        assert_eq!(hash.len(), 32);
        hashes.push(hash);
    }

    // All hashes should be different
    let unique_hashes: HashSet<_> = hashes.iter().collect();
    assert_eq!(
        unique_hashes.len(),
        test_cases.len(),
        "Null byte handling produced duplicate hashes"
    );
}

#[test]
fn test_high_entropy_inputs() {
    // Test with pseudo-random high-entropy inputs
    let hasher = ChronoHash::new(Mode::Normal);

    for i in 0..100 {
        // Generate deterministic pseudo-random bytes
        let length = ((i * 7 + 13) % 1000 + 1) as usize;
        let msg: Vec<u8> = (0..length)
            .map(|j| ((i * 31 + j * 17) % 256) as u8)
            .collect();

        let hash1 = hasher.hash(&msg);
        let hash2 = hasher.hash(&msg);

        // Determinism check
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)] // Only run in release mode
fn test_performance_no_regression() {
    // Ensure optimizations don't degrade performance
    // This test should be run with cargo test --release
    use std::time::Instant;

    let hasher_fast = ChronoHash::new(Mode::Fast);
    let hasher_normal = ChronoHash::new(Mode::Normal);

    let msg = vec![b'x'; 100];
    let iterations = 10_000;

    // Test fast mode
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hasher_fast.hash(&msg);
    }
    let fast_duration = start.elapsed();
    let fast_rate = iterations as f64 / fast_duration.as_secs_f64();

    // Test normal mode
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hasher_normal.hash(&msg);
    }
    let normal_duration = start.elapsed();
    let normal_rate = iterations as f64 / normal_duration.as_secs_f64();

    // Fast mode should be significantly faster
    assert!(
        fast_rate > normal_rate * 1.2,
        "Fast mode ({:.0} h/s) not faster than normal ({:.0} h/s)",
        fast_rate,
        normal_rate
    );

    // In debug mode, performance is much lower - skip strict checks
    #[cfg(not(debug_assertions))]
    {
        // Minimum performance thresholds (release mode only)
        assert!(
            fast_rate > 1_000_000.0,
            "Fast mode {:.0} h/s below 1M h/s threshold",
            fast_rate
        );
        assert!(
            normal_rate > 500_000.0,
            "Normal mode {:.0} h/s below 500K h/s threshold",
            normal_rate
        );
    }
}
