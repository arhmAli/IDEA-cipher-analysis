import sys
import time
import os
import csv

def multiplicative_inverse(a):
    mod = 0x10001
    if a == 0:
        a = 0x10000
    old_r, r = a, mod
    old_t, t = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_t, t = t, old_t - quotient * t
    return old_t % mod if old_r == 1 else 0

def generate_subkeys(key):
    subkeys = []
    current_key = key
    for _ in range(6):
        for i in range(8):
            subkey = (current_key >> (112 - 16*i)) & 0xFFFF
            subkeys.append(subkey)
        current_key = ((current_key << 25) | (current_key >> 103)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    for i in range(4):
        subkey = (current_key >> (112 - 16*i)) & 0xFFFF
        subkeys.append(subkey)
    return subkeys

def generate_decrypt_subkeys(encrypt_subkeys):
    decrypt_subkeys = []
    k49 = encrypt_subkeys[48]
    k50 = encrypt_subkeys[49]
    k51 = encrypt_subkeys[50]
    k52 = encrypt_subkeys[51]
    decrypt_subkeys.extend([
        multiplicative_inverse(k49),
        (-k50) % 0x10000,
        (-k51) % 0x10000,
        multiplicative_inverse(k52)
    ])
    for r in range(8, 0, -1):
        idx = (r-1)*6
        k = encrypt_subkeys[idx:idx+6]
        decrypt_subkeys.extend([
            multiplicative_inverse(k[0]),
            (-k[1]) % 0x10000,
            (-k[2]) % 0x10000,
            multiplicative_inverse(k[3]),
            k[4],
            k[5]
        ])
    return decrypt_subkeys

def idea_mul(a, b):
    mod = 0x10001
    a = a if a !=0 else 0x10000
    b = b if b !=0 else 0x10000
    return (a * b) % mod

def encrypt_block(block, subkeys):
    x1 = (block >> 48) & 0xFFFF
    x2 = (block >> 32) & 0xFFFF
    x3 = (block >> 16) & 0xFFFF
    x4 = block & 0xFFFF
    for i in range(8):
        k = subkeys[i*6 : i*6+6]
        s1 = idea_mul(x1, k[0])
        s2 = (x2 + k[1]) % 0x10000
        s3 = (x3 + k[2]) % 0x10000
        s4 = idea_mul(x4, k[3])
        s5 = s1 ^ s3
        s6 = s2 ^ s4
        s7 = idea_mul(s5, k[4])
        s8 = (s6 + s7) % 0x10000
        s9 = idea_mul(s8, k[5])
        s10 = (s7 + s9) % 0x10000
        x1, x2, x3, x4 = s1 ^ s9, s3 ^ s9, s2 ^ s10, s4 ^ s10
        if i < 7:
            x2, x3 = x3, x2
    y1 = idea_mul(x1, subkeys[48])
    y2 = (x2 + subkeys[49]) % 0x10000
    y3 = (x3 + subkeys[50]) % 0x10000
    y4 = idea_mul(x4, subkeys[51])
    return (y1 << 48) | (y2 << 32) | (y3 << 16) | y4

def decrypt_block(block, subkeys):
    return encrypt_block(block, subkeys)

def pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def process_file(in_file, out_file, subkeys, mode):
    with open(in_file, 'rb') as f:
        data = f.read()
    if mode == 'encrypt':
        data = pad(data)
    blocks = [int.from_bytes(data[i:i+8], 'big') for i in range(0, len(data), 8)]
    processed = []
    for block in blocks:
        if mode == 'encrypt':
            processed_block = encrypt_block(block, subkeys)
        else:
            processed_block = decrypt_block(block, subkeys)
        processed.append(processed_block.to_bytes(8, 'big'))
    result = b''.join(processed)
    if mode == 'decrypt':
        result = unpad(result)
    with open(out_file, 'wb') as f:
        f.write(result)

def main():
    key = int.from_bytes(b'ABCDEFGHIJKLMNOP', 'big')  # 16-byte key
    encrypt_subkeys = generate_subkeys(key)
    decrypt_subkeys = generate_decrypt_subkeys(encrypt_subkeys)
    
    # File configuration
    files = [
        ('1KB.bin', '1KB_enc.bin', '1KB_dec.bin'),
        ('10KB.bin', '10KB_enc.bin', '10KB_dec.bin'),
        ('100KB.bin', '100KB_enc.bin', '100KB_dec.bin'),
        ('1MB.bin', '1MB_enc.bin', '1MB_dec.bin'),
        ('10MB.bin', '10MB_enc.bin', '10MB_dec.bin'),
        ('100MB.bin', '100MB_enc.bin', '100MB_dec.bin'),
    ]
    
    results = []
    
    for in_file, enc_file, dec_file in files:
        if not os.path.exists(in_file):
            print(f"File {in_file} not found. Skipping...")
            continue
        
        # Encryption
        start = time.perf_counter()
        process_file(in_file, enc_file, encrypt_subkeys, 'encrypt')
        enc_time = time.perf_counter() - start
        
        # Decryption
        start = time.perf_counter()
        process_file(enc_file, dec_file, decrypt_subkeys, 'decrypt')
        dec_time = time.perf_counter() - start
        
        # Record results
        file_size = os.path.getsize(in_file)
        results.append({
            'File': in_file,
            'Size_KB': file_size / 1024,
            'Encrypt_Time': enc_time,
            'Decrypt_Time': dec_time
        })
        
        print(f"Processed {in_file} ({file_size/1024:.1f} KB)")
        print(f"  Encryption: {enc_time:.4f} sec")
        print(f"  Decryption: {dec_time:.4f} sec")
    
    # Save results to CSV
    with open('benchmark_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['File', 'Size_KB', 'Encrypt_Time', 'Decrypt_Time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    # Print summary
    print("\nBenchmark Summary:")
    print(f"{'File':<12} {'Size (KB)':<12} {'Encrypt (s)':<12} {'Decrypt (s)':<12}")
    for res in results:
        print(f"{res['File']:<12} {res['Size_KB']:<12.2f} {res['Encrypt_Time']:<12.4f} {res['Decrypt_Time']:<12.4f}")

if __name__ == "__main__":
    main()