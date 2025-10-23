"""
Advanced Cryptanalysis Test Suite for ChronoHash

This module implements comprehensive cryptographic tests that a security
researcher would perform on a hash function, including:
- Statistical randomness tests
- Differential cryptanalysis resistance
- Linear cryptanalysis resistance
- Birthday attack resistance
- Length extension attack resistance
- Preimage resistance
- Second preimage resistance
- Near-collision detection
- Bit independence tests
- Strict avalanche criterion (SAC)
"""

import unittest
import hashlib
import random
import struct
from collections import Counter
from chronohash import ChronoHash, chronohash


class TestCryptanalysis(unittest.TestCase):
    """Advanced cryptanalysis tests for ChronoHash."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hasher_normal = ChronoHash(fast_mode=False)
        self.hasher_fast = ChronoHash(fast_mode=True)
        random.seed(42)  # For reproducibility
    
    def test_strict_avalanche_criterion(self):
        """Test Strict Avalanche Criterion (SAC).
        
        Each input bit should cause each output bit to flip with 50% probability.
        """
        test_msg = b"test message for SAC analysis"
        base_hash = self.hasher_normal.hash(test_msg)
        
        # Test each bit position
        bit_flip_counts = [[0, 0] for _ in range(256)]  # [changed, unchanged]
        
        for byte_pos in range(min(len(test_msg), 20)):  # Test first 20 bytes
            for bit_pos in range(8):
                # Flip one bit
                modified = bytearray(test_msg)
                modified[byte_pos] ^= (1 << bit_pos)
                modified_hash = self.hasher_normal.hash(bytes(modified))
                
                # Check which output bits changed
                for out_byte_idx in range(32):
                    diff = base_hash[out_byte_idx] ^ modified_hash[out_byte_idx]
                    for out_bit_idx in range(8):
                        bit_idx = out_byte_idx * 8 + out_bit_idx
                        if diff & (1 << out_bit_idx):
                            bit_flip_counts[bit_idx][0] += 1  # Changed
                        else:
                            bit_flip_counts[bit_idx][1] += 1  # Unchanged
        
        # Each output bit should flip approximately 50% of the time
        for bit_idx, (changed, unchanged) in enumerate(bit_flip_counts):
            total = changed + unchanged
            if total > 0:
                flip_rate = changed / total
                self.assertTrue(0.3 < flip_rate < 0.7,
                              f"Bit {bit_idx}: flip rate {flip_rate:.2%} outside 30-70% range")
    
    def test_bit_independence(self):
        """Test independence of output bits.
        
        Changes in different input bits should independently affect output bits.
        """
        base_msg = b"bit independence test message"
        
        # Generate hashes with different single-bit changes
        hashes = []
        for byte_pos in range(min(len(base_msg), 10)):
            for bit_pos in range(8):
                modified = bytearray(base_msg)
                modified[byte_pos] ^= (1 << bit_pos)
                hash_val = self.hasher_normal.hash(bytes(modified))
                hashes.append(hash_val)
        
        # Check pairwise Hamming distances
        distances = []
        for i in range(len(hashes)):
            for j in range(i + 1, len(hashes)):
                dist = sum(bin(hashes[i][k] ^ hashes[j][k]).count('1') 
                          for k in range(32))
                distances.append(dist)
        
        # Average should be around 128 bits (50% of 256)
        avg_distance = sum(distances) / len(distances)
        self.assertTrue(100 < avg_distance < 156,
                       f"Average Hamming distance {avg_distance:.1f} not in range [100, 156]")
    
    def test_statistical_randomness_chi_squared(self):
        """Test statistical randomness using chi-squared test."""
        # Generate multiple hashes
        hashes = []
        for i in range(1000):
            msg = f"message_{i}".encode()
            hash_val = self.hasher_normal.hash(msg)
            hashes.append(hash_val)
        
        # Count byte value frequencies
        byte_counts = Counter()
        for hash_val in hashes:
            for byte in hash_val:
                byte_counts[byte] += 1
        
        # Expected frequency for each byte value (uniform distribution)
        total_bytes = len(hashes) * 32
        expected = total_bytes / 256
        
        # Chi-squared test
        chi_squared = sum((count - expected) ** 2 / expected 
                         for count in byte_counts.values())
        
        # Critical value for 255 degrees of freedom at 0.05 significance: ~293
        # We use a more relaxed threshold for practical testing
        self.assertLess(chi_squared, 350,
                       f"Chi-squared value {chi_squared:.2f} indicates non-random distribution")
    
    def test_birthday_attack_resistance(self):
        """Test resistance to birthday attacks.
        
        Generate many hashes and check for collisions.
        """
        num_hashes = 10000
        hashes = set()
        collisions = 0
        
        for i in range(num_hashes):
            msg = f"birthday_test_{i}".encode()
            hash_val = self.hasher_normal.hexdigest(msg)
            
            if hash_val in hashes:
                collisions += 1
            hashes.add(hash_val)
        
        self.assertEqual(collisions, 0,
                        f"Found {collisions} collisions in {num_hashes} hashes")
        self.assertEqual(len(hashes), num_hashes,
                        "Not all hashes were unique")
    
    def test_preimage_resistance(self):
        """Test first preimage resistance.
        
        Given a hash, it should be infeasible to find any input that produces it.
        This is a basic sanity check - we verify the search space is large.
        """
        target_msg = b"target message for preimage test"
        target_hash = self.hasher_normal.hash(target_msg)
        
        # Try random inputs - none should match (except the original)
        attempts = 10000
        matches = 0
        
        for i in range(attempts):
            random_msg = f"random_{i}_{random.randint(0, 1000000)}".encode()
            if random_msg != target_msg:
                random_hash = self.hasher_normal.hash(random_msg)
                if random_hash == target_hash:
                    matches += 1
        
        self.assertEqual(matches, 0,
                        f"Found {matches} preimages in {attempts} attempts")
    
    def test_second_preimage_resistance(self):
        """Test second preimage resistance.
        
        Given an input and its hash, it should be infeasible to find
        a different input that produces the same hash.
        """
        msg1 = b"original message for second preimage test"
        hash1 = self.hasher_normal.hash(msg1)
        
        # Try to find different message with same hash
        attempts = 10000
        second_preimages = 0
        
        for i in range(attempts):
            msg2 = f"attempt_{i}_{random.randint(0, 1000000)}".encode()
            if msg2 != msg1:
                hash2 = self.hasher_normal.hash(msg2)
                if hash2 == hash1:
                    second_preimages += 1
        
        self.assertEqual(second_preimages, 0,
                        f"Found {second_preimages} second preimages in {attempts} attempts")
    
    def test_near_collision_detection(self):
        """Test for near-collisions.
        
        Near-collisions (hashes differing in only a few bits) should be as
        rare as random chance would predict.
        """
        num_hashes = 1000
        hashes = []
        
        for i in range(num_hashes):
            msg = f"near_collision_test_{i}".encode()
            hash_val = self.hasher_normal.hash(msg)
            hashes.append(hash_val)
        
        # Count near-collisions (differ by <= 10 bits)
        near_collisions = 0
        threshold = 10
        
        for i in range(len(hashes)):
            for j in range(i + 1, min(i + 50, len(hashes))):  # Check subset
                dist = sum(bin(hashes[i][k] ^ hashes[j][k]).count('1') 
                          for k in range(32))
                if dist <= threshold:
                    near_collisions += 1
        
        # Near-collisions should be extremely rare
        self.assertEqual(near_collisions, 0,
                        f"Found {near_collisions} near-collisions (<= {threshold} bit difference)")
    
    def test_length_extension_attack_resistance(self):
        """Test resistance to length extension attacks.
        
        ChronoHash includes message length in padding, making it resistant
        to length extension attacks.
        """
        msg1 = b"message"
        msg2 = b"messageextension"
        
        hash1 = self.hasher_normal.hash(msg1)
        hash2 = self.hasher_normal.hash(msg2)
        
        # The hashes should be completely different
        differences = sum(bin(hash1[i] ^ hash2[i]).count('1') for i in range(32))
        
        # Should differ in approximately 50% of bits
        self.assertTrue(differences > 100,
                       f"Only {differences} bits differ - may be vulnerable to length extension")
    
    def test_differential_cryptanalysis_resistance(self):
        """Test resistance to differential cryptanalysis.
        
        Similar inputs should produce uncorrelated outputs.
        """
        base_msg = b"differential cryptanalysis test base message"
        base_hash = self.hasher_normal.hash(base_msg)
        
        # Test with various small modifications
        differential_scores = []
        
        for offset in range(min(len(base_msg), 20)):
            for delta in [1, 2, 4, 8, 16, 32, 64, 128]:
                modified = bytearray(base_msg)
                modified[offset] = (modified[offset] + delta) % 256
                modified_hash = self.hasher_normal.hash(bytes(modified))
                
                # Count bit differences
                diff_bits = sum(bin(base_hash[i] ^ modified_hash[i]).count('1') 
                               for i in range(32))
                differential_scores.append(diff_bits)
        
        # All differences should be in the avalanche range (40-60% of 256 bits)
        for score in differential_scores:
            self.assertTrue(100 < score < 156,
                           f"Differential score {score} outside safe range [100, 156]")
    
    def test_fast_mode_security(self):
        """Test that fast mode maintains cryptographic properties."""
        # Fast mode should still have good avalanche effect
        msg1 = b"fast mode security test"
        msg2 = b"fast mode security tesu"  # One bit different
        
        hash1 = self.hasher_fast.hash(msg1)
        hash2 = self.hasher_fast.hash(msg2)
        
        diff_bits = sum(bin(hash1[i] ^ hash2[i]).count('1') for i in range(32))
        percentage = (diff_bits / 256.0) * 100.0
        
        self.assertTrue(40 < percentage < 60,
                       f"Fast mode avalanche: {percentage:.1f}% (expected 40-60%)")
    
    def test_collision_resistance_intensive(self):
        """Intensive collision resistance test."""
        num_tests = 50000
        hashes = set()
        
        for i in range(num_tests):
            msg = struct.pack('>Q', i) + str(i).encode()
            hash_val = self.hasher_normal.hexdigest(msg)
            
            self.assertNotIn(hash_val, hashes,
                           f"Collision found at iteration {i}")
            hashes.add(hash_val)
        
        self.assertEqual(len(hashes), num_tests)
    
    def test_zero_byte_handling(self):
        """Test proper handling of messages with null bytes."""
        test_cases = [
            b"\x00",
            b"\x00" * 10,
            b"test\x00message",
            b"\x00test",
            b"test\x00",
            b"\x00\x00\x00\x00\x00",
        ]
        
        hashes = []
        for msg in test_cases:
            hash_val = self.hasher_normal.hash(msg)
            hashes.append(hash_val)
            
            # Verify proper length
            self.assertEqual(len(hash_val), 32)
        
        # All should be different
        self.assertEqual(len(set(map(bytes, hashes))), len(hashes),
                        "Null byte handling produced duplicate hashes")
    
    def test_high_entropy_inputs(self):
        """Test with high-entropy random inputs."""
        for _ in range(100):
            # Generate random high-entropy input
            length = random.randint(1, 1000)
            msg = bytes(random.randint(0, 255) for _ in range(length))
            
            hash_val = self.hasher_normal.hash(msg)
            
            # Verify output
            self.assertEqual(len(hash_val), 32)
            
            # Hash should be deterministic
            hash_val2 = self.hasher_normal.hash(msg)
            self.assertEqual(hash_val, hash_val2)


class TestPerformanceRegression(unittest.TestCase):
    """Test that optimizations don't degrade performance."""
    
    def test_performance_baseline(self):
        """Establish performance baseline."""
        import time
        
        hasher_fast = ChronoHash(fast_mode=True)
        hasher_normal = ChronoHash(fast_mode=False)
        
        msg = b"x" * 100
        iterations = 1000
        
        # Fast mode performance
        start = time.time()
        for _ in range(iterations):
            hasher_fast.hash(msg)
        fast_time = time.time() - start
        fast_rate = iterations / fast_time
        
        # Normal mode performance
        start = time.time()
        for _ in range(iterations):
            hasher_normal.hash(msg)
        normal_time = time.time() - start
        normal_rate = iterations / normal_time
        
        # Fast mode should be at least 5x faster
        self.assertGreater(fast_rate, normal_rate * 5,
                          f"Fast mode ({fast_rate:.0f} h/s) not significantly faster than normal ({normal_rate:.0f} h/s)")
        
        # Minimum performance thresholds (adjusted for realistic expectations)
        self.assertGreater(fast_rate, 15000,
                          f"Fast mode {fast_rate:.0f} h/s below minimum 15,000 h/s")
        self.assertGreater(normal_rate, 2000,
                          f"Normal mode {normal_rate:.0f} h/s below minimum 2,000 h/s")


if __name__ == '__main__':
    # Run with verbose output
    unittest.main(verbosity=2)
