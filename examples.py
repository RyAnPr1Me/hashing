"""
ChronoHash Usage Examples

This file demonstrates various use cases for the ChronoHash algorithm.
"""

from chronohash import ChronoHash, chronohash


def example_basic_usage():
    """Basic usage examples."""
    print("=" * 60)
    print("Example 1: Basic Usage")
    print("=" * 60)
    
    # Simple string hashing
    message = b"Hello, World!"
    hash_value = chronohash(message)
    print(f"Message: {message.decode()}")
    print(f"Hash:    {hash_value}")
    print()


def example_file_integrity():
    """Example: Verify file integrity."""
    print("=" * 60)
    print("Example 2: File Integrity Check")
    print("=" * 60)
    
    # Simulate file content
    file_content = b"This is the content of my important file."
    
    # Create hash
    original_hash = chronohash(file_content)
    print(f"Original file hash: {original_hash}")
    
    # Later, verify the file hasn't changed
    current_content = b"This is the content of my important file."
    current_hash = chronohash(current_content)
    
    if original_hash == current_hash:
        print("✓ File integrity verified - content unchanged")
    else:
        print("✗ File has been modified!")
    print()


def example_password_hashing():
    """Example: Hash passwords (note: use proper password hashing in production)."""
    print("=" * 60)
    print("Example 3: Password Hashing (Educational)")
    print("=" * 60)
    print("Note: For production, use bcrypt, scrypt, or Argon2")
    print()
    
    # Hash a password
    password = b"mySecurePassword123"
    password_hash = chronohash(password)
    
    print(f"Password hash: {password_hash}")
    
    # Verify password
    input_password = b"mySecurePassword123"
    if chronohash(input_password) == password_hash:
        print("✓ Password verified!")
    else:
        print("✗ Invalid password")
    print()


def example_data_deduplication():
    """Example: Data deduplication."""
    print("=" * 60)
    print("Example 4: Data Deduplication")
    print("=" * 60)
    
    # Simulate a data store
    data_store = {}
    
    documents = [
        (b"Document 1 content", "doc1.txt"),
        (b"Document 2 content", "doc2.txt"),
        (b"Document 1 content", "doc1_copy.txt"),  # Duplicate!
        (b"Unique document", "doc3.txt"),
    ]
    
    for content, filename in documents:
        hash_value = chronohash(content)
        
        if hash_value in data_store:
            print(f"{filename}: Duplicate of {data_store[hash_value]}")
        else:
            data_store[hash_value] = filename
            print(f"{filename}: Stored (hash: {hash_value[:16]}...)")
    
    print(f"\nTotal unique documents: {len(data_store)}")
    print()


def example_hash_table():
    """Example: Using hash for hash table keys."""
    print("=" * 60)
    print("Example 5: Hash Table / Dictionary Keys")
    print("=" * 60)
    
    # Create a hash table using ChronoHash
    hash_table = {}
    
    items = [
        ("apple", "A red fruit"),
        ("banana", "A yellow fruit"),
        ("cherry", "A small red fruit"),
        ("apple", "Another apple"),  # Will overwrite
    ]
    
    for key, value in items:
        hash_key = chronohash(key.encode())
        hash_table[hash_key] = value
        print(f"Stored '{key}' with hash {hash_key[:16]}...")
    
    # Retrieve
    print("\nRetrieving 'banana':")
    banana_hash = chronohash(b"banana")
    if banana_hash in hash_table:
        print(f"Found: {hash_table[banana_hash]}")
    print()


def example_comparing_inputs():
    """Example: Compare similar inputs."""
    print("=" * 60)
    print("Example 6: Comparing Similar Inputs")
    print("=" * 60)
    
    inputs = [
        b"The quick brown fox",
        b"The quick brown fox!",  # Added punctuation
        b"The quick brown dog",   # Changed word
        b"the quick brown fox",   # Changed case
    ]
    
    print("Notice how small changes produce completely different hashes:\n")
    
    for inp in inputs:
        hash_val = chronohash(inp)
        print(f"Input: {inp.decode():<25} Hash: {hash_val[:32]}...")
    print()


def example_detect_tampering():
    """Example: Detect data tampering."""
    print("=" * 60)
    print("Example 7: Detect Data Tampering")
    print("=" * 60)
    
    # Original message with hash
    message = b"Transfer $100 to account A"
    original_hash = chronohash(message)
    
    print(f"Original: {message.decode()}")
    print(f"Hash:     {original_hash}\n")
    
    # Someone tries to tamper
    tampered = b"Transfer $999 to account B"
    tampered_hash = chronohash(tampered)
    
    print(f"Received: {tampered.decode()}")
    print(f"Hash:     {tampered_hash}\n")
    
    if original_hash == tampered_hash:
        print("✓ Message is authentic")
    else:
        print("✗ WARNING: Message has been tampered with!")
    print()


def example_batch_processing():
    """Example: Batch hash generation."""
    print("=" * 60)
    print("Example 8: Batch Processing")
    print("=" * 60)
    
    hasher = ChronoHash()
    
    # Process multiple items
    items = [f"Item {i}" for i in range(10)]
    
    print("Hashing 10 items...")
    hashes = []
    for item in items:
        h = hasher.hexdigest(item.encode())
        hashes.append(h)
        print(f"{item}: {h[:24]}...")
    
    print(f"\nAll hashes unique: {len(hashes) == len(set(hashes))}")
    print()


def example_dynamic_rounds():
    """Example: Demonstrating dynamic rounds feature."""
    print("=" * 60)
    print("Example 9: Dynamic Rounds Feature")
    print("=" * 60)
    
    hasher = ChronoHash()
    
    # Low complexity input
    simple = b"aaaaaaaaaa"
    simple_rounds = hasher._calculate_dynamic_rounds(simple)
    simple_hash = hasher.hexdigest(simple)
    
    # High complexity input
    complex_input = bytes(range(128))
    complex_rounds = hasher._calculate_dynamic_rounds(complex_input)
    complex_hash = hasher.hexdigest(complex_input)
    
    print(f"Low complexity input:  {simple_rounds} rounds")
    print(f"Hash: {simple_hash[:40]}...")
    print()
    print(f"High complexity input: {complex_rounds} rounds")
    print(f"Hash: {complex_hash[:40]}...")
    print()
    print(f"Complex input gets {complex_rounds - simple_rounds} extra rounds!")
    print()


def example_binary_data():
    """Example: Hashing binary data."""
    print("=" * 60)
    print("Example 10: Binary Data")
    print("=" * 60)
    
    # Various binary patterns
    binary_data = [
        (b"\x00" * 16, "Null bytes"),
        (b"\xff" * 16, "High bytes"),
        (bytes(range(256)), "All byte values"),
        (b"\x01\x02\x04\x08\x10\x20\x40\x80", "Powers of 2"),
    ]
    
    for data, description in binary_data:
        hash_val = chronohash(data)
        print(f"{description:<20} {hash_val[:32]}...")
    print()


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 15 + "ChronoHash Usage Examples" + " " * 18 + "║")
    print("╚" + "═" * 58 + "╝")
    print()
    
    example_basic_usage()
    example_file_integrity()
    example_password_hashing()
    example_data_deduplication()
    example_hash_table()
    example_comparing_inputs()
    example_detect_tampering()
    example_batch_processing()
    example_dynamic_rounds()
    example_binary_data()
    
    print("=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
