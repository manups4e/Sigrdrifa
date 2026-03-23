# Sigrdrifa v1.0
### Universal Cryptographic Suite for FiveM (Shared Environment)

Sigrdrifa is a high-performance cryptographic wrapper developed for the FiveM platform, designed to provide a unified security layer for both Client and Server environments. By utilizing a shared-script architecture, it ensures seamless data parity and symmetric encryption/decryption across the network.

---

## Technical Architecture

The suite is built upon three primary pillars:
1. **Asymmetric Exchange**: Curve25519 implementation for Diffie-Hellman key exchange protocols.
2. **Hashing Engine**: Integration with a comprehensive library supporting SHA-2, SHA-3, and the high-speed BLAKE3 algorithm.
3. **Symmetric Layer**: A robust XOR-based stream cipher utilizing SHA-derived key rotation for data obfuscation.

---

## Implementation Requirements

Sigrdrifa can be used either as a **standalone resource** (via exports) or by **integrating it directly** into your own project. To maintain cryptographic integrity and ensure proper dependency resolution, the following files must be loaded as `shared_scripts` in your `fxmanifest.lua` in this specific order:

```lua
fx_version 'cerulean'
game 'gta5'

shared_scripts {
    'lib/sha.lua',           -- Core Hashing Library
    'lib/curve25519.lua',    -- Elliptic Curve Mathematics
    'lib/encryption.lua'     -- Sigrdrifa Wrapper
}
```

---

## API Reference (Exports)

### Default Algorithm Specification

Sigrdrifa is designed with a "Secure-by-Default" philosophy. For both encryption and decryption operations, the suite implements a fallback mechanism:

- **Encryption**: If no algorithm is explicitly defined in the `algo` parameter, the system defaults to **SHA-256** for key derivation.
- **Decryption**: The system will automatically attempt to validate the payload using the internal Magic Marker. If no specific algorithm is forced, it will iterate through the supported algorithms, starting with **SHA-256** as the primary candidate.

#### Example of Default Usage
```lua
-- This will automatically use SHA-256
local encrypted = exports['sigrdrifa']:Encrypt(myData, myKey)

-- This will automatically detect the algorithm or fallback to SHA-256
local decrypted = exports['sigrdrifa']:Decrypt(encrypted, myKey)
```

To optimize performance for high-frequency data (e.g., entity positions or inventory sync), it is recommended to explicitly pass `Encryption.Algos.BLAKE3` to override the default SHA-256 behavior.


### Object Encryption
Encrypts any Lua data type (tables, strings, numbers, booleans) using JSON serialization as the intermediate transport format.

```lua
-- Syntax: exports['sigrdrifa']:EncryptObject(object, key, algorithm)
local data = { accountId = 550, balance = 25000 }
local encrypted = exports['sigrdrifa']:EncryptObject(data, "session_secret", "blake3")
```

### Object Decryption
Automatically detects the encryption algorithm via the internal Magic Marker (FX!) and restores the original Lua object.

```lua
-- Syntax: exports['sigrdrifa']:DecryptObject(byteTable, key)
local decoded, err = exports['sigrdrifa']:DecryptObject(encrypted, "session_secret")

if not decoded then
    -- Handle error (e.g., "INVALID_KEY_OR_ALGO")
    print("Security Error: " .. err)
end
```

### Utility and Transformation
- **GetAlgos**: Returns the `Encryption.Algos` enum for type-safe algorithm selection.
- **ToBase64**: Encodes encrypted byte tables into Base64 strings for stable network transmission via standard FiveM events.
- **ToHex**: Converts byte arrays to hexadecimal strings for logging purposes.
- **ToEscapedString**: Sanitizes binary data for console output, escaping control characters like `\n` to prevent terminal formatting issues.

---

## Security Best Practices

1. **Algorithm Selection**: For high-frequency server-side operations, the use of `BLAKE3` is recommended due to its superior throughput and minimal CPU overhead compared to SHA-256.
2. **Key Management**: While the logic is shared, private keys must remain local to their respective environments. Use Curve25519 to establish a unique Shared Secret for each session.
3. **Network Transit**: Always encode encrypted byte tables to Base64 using `ToBase64` before passing them through `TriggerServerEvent` or `TriggerClientEvent` to avoid data corruption from null-bytes or control characters.

---

## License
Distributed under the MIT License. Optimized for secure resource communication in complex FiveM environments.