# TGA Image Cipher

A C++ implementation of streaming image-data encryption and decryption for TGA files, using OpenSSL's EVP cryptography API.

## Overview

Implement two functions that encrypt and decrypt a simplified TGA file format. The 18-byte fixed header remains unchanged; the rest of the file is processed as data.

| File section | Handling |
| --- | --- |
| Fixed header | The first 18 bytes are copied without modification. |
| Optional header data | Treated as image data and encrypted or decrypted. |
| Image data | Encrypted or decrypted. |

The decrypted output should be byte-for-byte identical to the original input.

## Required Interface

```cpp
int encrypt_data(const std::string & in_filename,
                 const std::string & out_filename,
                 crypto_config & config);

int decrypt_data(const std::string & in_filename,
                 const std::string & out_filename,
                 crypto_config & config);
```

Both functions return `EXIT_SUCCESS` on success and `EXIT_FAILURE` on failure. Failure includes invalid or inaccessible input files, read or write errors, and invalid cryptographic configuration that cannot be used or repaired.

## Configuration

`crypto_config` provides:

- The selected symmetric cipher by name.
- A shared key and its length.
- An initialization vector (IV) and its length.

### Encryption

Before encrypting, `encrypt_data` must check that the key and IV are long enough for the selected cipher.

- If the key is missing or too short, generate a cryptographically secure key and update both the key and its recorded length in `config`.
- If the cipher uses an IV and the IV is missing or too short, generate a cryptographically secure IV and update it and its recorded length in `config`.
- Do not replace a key or IV that is already long enough, even if it is longer than required.
- Some ciphers do not use an IV. Do not generate one for those ciphers.

### Decryption

`decrypt_data` must not generate or repair a key or IV. If the key or required IV is missing or too short, return `EXIT_FAILURE`.

## Implementation Notes

- OpenSSL's EVP API provides `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, and `EVP_EncryptFinal_ex`, and the corresponding decryption functions. Check the OpenSSL documentation for higher-level alternatives that may simplify the implementation.
- Block ciphers use padding by default. The encrypted file may therefore be larger than the input; this is expected and should not be disabled.
- Input files may be larger than available memory. Process data incrementally instead of loading the entire file, or large portions of it, into memory.
- Check the return value of every operation and release dynamically allocated resources on every failure path.
- Keys and IVs are binary data, not text strings. Do not handle them as null-terminated ASCII strings.
- `crypto_config` uses `std::unique_ptr`. `std::make_unique` is suitable for allocation, and `.get()` can be used when an API requires a raw pointer.

## Why Leave the Header Unencrypted?

Keeping the TGA header intact allows image viewers such as GIMP to recognize and display the encrypted file. Viewing results produced with different block cipher modes, such as ECB and CBC, also illustrates how a poorly chosen mode can reveal image patterns even when a modern cipher is used.

## Test Data

The assignment materials include example runs and test images with matching encrypted versions produced using a block cipher.