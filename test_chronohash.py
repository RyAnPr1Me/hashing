"""
Test suite for ChronoHash algorithm.

Tests cover:
- Basic functionality
- Hash properties (determinism, avalanche effect, collision resistance)
- Performance characteristics
- Comparison with SHA-256
"""

import unittest
import hashlib
import time
from chronohash import ChronoHash, chronohash


class TestChronoHashBasics(unittest.TestCase):
    """Test basic functionality of ChronoHash."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hasher = ChronoHash()
    
    def test_empty_string(self):
        """Test hashing empty string."""
        digest = self.hasher.hexdigest(b"")
        self.assertEqual(len(digest), 64)  # 256 bits = 64 hex chars
        self.assertIsInstance(digest, str)
    
    def test_single_byte(self):
        """Test hashing single byte."""
        digest = self.hasher.hexdigest(b"a")
        self.assertEqual(len(digest), 64)
    
    def test_multiple_inputs(self):
        """Test various input lengths."""
        test_cases = [
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            b"0123456789" * 10,
            b"x" * 1000,
        ]
        
        for msg in test_cases:
            digest = self.hasher.hexdigest(msg)
            self.assertEqual(len(digest), 64, f"Failed for input length {len(msg)}")
            # Verify it's valid hex
            int(digest, 16)
    
    def test_convenience_function(self):
        """Test convenience function."""
        msg = b"test message"
        digest1 = chronohash(msg)
        digest2 = self.hasher.hexdigest(msg)
        self.assertEqual(digest1, digest2)


class TestHashProperties(unittest.TestCase):
    """Test cryptographic properties of ChronoHash."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hasher = ChronoHash()
    
    def test_determinism(self):
        """Test that same input always produces same output."""
        msg = b"determinism test"
        digest1 = self.hasher.hexdigest(msg)
        digest2 = self.hasher.hexdigest(msg)
        digest3 = self.hasher.hexdigest(msg)
        
        self.assertEqual(digest1, digest2)
        self.assertEqual(digest2, digest3)
    
    def test_different_inputs_different_outputs(self):
        """Test that different inputs produce different outputs."""
        msg1 = b"abc"
        msg2 = b"abd"
        msg3 = b"abcd"
        
        digest1 = self.hasher.hexdigest(msg1)
        digest2 = self.hasher.hexdigest(msg2)
        digest3 = self.hasher.hexdigest(msg3)
        
        self.assertNotEqual(digest1, digest2)
        self.assertNotEqual(digest2, digest3)
        self.assertNotEqual(digest1, digest3)
    
    def test_avalanche_effect(self):
        """
        Test avalanche effect: small change in input causes large change in output.
        A good hash should have ~50% bit difference for 1-bit input change.
        """
        msg1 = b"test message"
        msg2 = b"test messagf"  # Changed last 'e' to 'f' (1 bit difference)
        
        digest1 = self.hasher.hash(msg1)
        digest2 = self.hasher.hash(msg2)
        
        # Count differing bits
        diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(digest1, digest2))
        total_bits = len(digest1) * 8
        
        # Avalanche effect should cause ~50% bits to flip
        # We'll accept 40-60% as good avalanche
        percentage = (diff_bits / total_bits) * 100
        self.assertGreater(percentage, 40, 
                          f"Avalanche effect too weak: only {percentage:.1f}% bits changed")
        self.assertLess(percentage, 60,
                       f"Avalanche effect too strong: {percentage:.1f}% bits changed")
    
    def test_length_extension_resistance(self):
        """Test that appending data creates completely different hash."""
        msg1 = b"message"
        msg2 = b"message" + b"x"
        
        digest1 = self.hasher.hexdigest(msg1)
        digest2 = self.hasher.hexdigest(msg2)
        
        self.assertNotEqual(digest1, digest2)
        # Should have significant difference
        diff_bits = sum(bin(b1 ^ b2).count('1') 
                       for b1, b2 in zip(bytes.fromhex(digest1), bytes.fromhex(digest2)))
        self.assertGreater(diff_bits, 50)  # At least 50 bits different
    
    def test_order_sensitivity(self):
        """Test that order of bytes matters."""
        msg1 = b"abc"
        msg2 = b"bca"
        msg3 = b"cab"
        
        digest1 = self.hasher.hexdigest(msg1)
        digest2 = self.hasher.hexdigest(msg2)
        digest3 = self.hasher.hexdigest(msg3)
        
        # All should be different
        self.assertNotEqual(digest1, digest2)
        self.assertNotEqual(digest2, digest3)
        self.assertNotEqual(digest1, digest3)
    
    def test_no_obvious_collisions(self):
        """Test a batch of inputs for obvious collisions."""
        hashes = {}
        
        # Test 1000 different inputs
        for i in range(1000):
            msg = f"test message {i}".encode()
            digest = self.hasher.hexdigest(msg)
            
            # Check for collision
            self.assertNotIn(digest, hashes, 
                           f"Collision found: {msg} and {hashes.get(digest)}")
            hashes[digest] = msg


class TestDynamicRounds(unittest.TestCase):
    """Test dynamic round calculation feature."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hasher = ChronoHash()
    
    def test_dynamic_rounds_increase(self):
        """Test that more complex inputs get more rounds."""
        # Low complexity: repeated bytes
        simple_msg = b"aaaaaaaaaa"
        simple_rounds = self.hasher._calculate_dynamic_rounds(simple_msg)
        
        # High complexity: random bytes
        complex_msg = bytes(range(256))
        complex_rounds = self.hasher._calculate_dynamic_rounds(complex_msg)
        
        self.assertGreater(complex_rounds, simple_rounds,
                          "More complex input should have more rounds")
    
    def test_base_rounds(self):
        """Test that base rounds are applied."""
        rounds = self.hasher._calculate_dynamic_rounds(b"test")
        self.assertGreaterEqual(rounds, 16)


class TestPerformance(unittest.TestCase):
    """Test performance characteristics."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hasher = ChronoHash()
    
    def test_reasonable_speed(self):
        """Test that hashing completes in reasonable time."""
        msg = b"x" * 10000  # 10KB message
        
        start = time.time()
        digest = self.hasher.hexdigest(msg)
        elapsed = time.time() - start
        
        # Should complete in under 1 second for 10KB
        self.assertLess(elapsed, 1.0, 
                       f"Hashing 10KB took {elapsed:.3f}s, too slow")
    
    def test_consistent_output_size(self):
        """Test that output is always 256 bits regardless of input size."""
        test_sizes = [0, 1, 10, 100, 1000, 10000]
        
        for size in test_sizes:
            msg = b"x" * size
            digest = self.hasher.hash(msg)
            self.assertEqual(len(digest), 32,  # 32 bytes = 256 bits
                           f"Wrong output size for input of {size} bytes")


class TestComparisonWithSHA256(unittest.TestCase):
    """Compare ChronoHash characteristics with SHA-256."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.chronohash = ChronoHash()
    
    def test_output_size_matches_sha256(self):
        """Test that output size matches SHA-256."""
        msg = b"test"
        chrono_digest = self.chronohash.hash(msg)
        sha_digest = hashlib.sha256(msg).digest()
        
        self.assertEqual(len(chrono_digest), len(sha_digest))
    
    def test_different_from_sha256(self):
        """Test that ChronoHash produces different hashes than SHA-256."""
        test_messages = [
            b"",
            b"a",
            b"abc",
            b"The quick brown fox jumps over the lazy dog",
        ]
        
        for msg in test_messages:
            chrono_digest = self.chronohash.hexdigest(msg)
            sha_digest = hashlib.sha256(msg).hexdigest()
            
            self.assertNotEqual(chrono_digest, sha_digest,
                              f"ChronoHash should differ from SHA-256 for: {msg}")
    
    def test_comparable_avalanche(self):
        """Test that avalanche effect is comparable to SHA-256."""
        msg1 = b"test message"
        msg2 = b"test messagf"
        
        # ChronoHash avalanche
        chrono_digest1 = self.chronohash.hash(msg1)
        chrono_digest2 = self.chronohash.hash(msg2)
        chrono_diff = sum(bin(b1 ^ b2).count('1') 
                         for b1, b2 in zip(chrono_digest1, chrono_digest2))
        
        # SHA-256 avalanche
        sha_digest1 = hashlib.sha256(msg1).digest()
        sha_digest2 = hashlib.sha256(msg2).digest()
        sha_diff = sum(bin(b1 ^ b2).count('1') 
                      for b1, b2 in zip(sha_digest1, sha_digest2))
        
        # Both should have good avalanche (around 128 bits for 256-bit hash)
        self.assertGreater(chrono_diff, 100, "ChronoHash avalanche too weak")
        self.assertGreater(sha_diff, 100, "SHA-256 avalanche baseline check")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hasher = ChronoHash()
    
    def test_null_bytes(self):
        """Test handling of null bytes."""
        msg = b"\x00" * 100
        digest = self.hasher.hexdigest(msg)
        self.assertEqual(len(digest), 64)
    
    def test_high_bytes(self):
        """Test handling of high byte values."""
        msg = b"\xff" * 100
        digest = self.hasher.hexdigest(msg)
        self.assertEqual(len(digest), 64)
    
    def test_binary_data(self):
        """Test handling of arbitrary binary data."""
        msg = bytes(range(256))
        digest = self.hasher.hexdigest(msg)
        self.assertEqual(len(digest), 64)
    
    def test_very_long_input(self):
        """Test handling of very long input."""
        msg = b"x" * 100000  # 100KB
        digest = self.hasher.hexdigest(msg)
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
