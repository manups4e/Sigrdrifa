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

## Curve25519 Handshake Protocol

To achieve maximum security, Sigrdrifa implements the Elliptic Curve Diffie-Hellman (ECDH) protocol. This allows the Client and Server to derive a **Shared Secret** without ever exchanging private keys over the network.



---

### Implementation Example

#### 1. Client-Side Initialization
The client generates a temporary key pair and transmits only the Public Key to the server.

```lua
local myKeys = nil
local secureSessionKey = nil

Citizen.CreateThread(function()
    -- Generate local Private and Public keys
    myKeys = exports['sigrdrifa']:GenerateKeyPair()
    
    -- Send ONLY the Public Key to the server
    TriggerServerEvent('sigrdrifa:initiateHandshake', myKeys.publicKey)
end)

-- Receive the Server's Public Key to complete the bridge
RegisterNetEvent('sigrdrifa:finalizeHandshake', function(serverPublicKey)
    -- Derive the Shared Secret: (My Private Key + Server Public Key)
    -- This 'secureSessionKey' is a byte table ready for Encrypt/Decrypt
    secureSessionKey = exports['sigrdrifa']:GetSharedSecret(myKeys.privateKey, serverPublicKey)
    
    print("Secure bridge established. Ready for encrypted transmission.")
end)
```

#### 2. Server-Side Handshake Management
The server receives the client's public key, generates its own pair, and calculates the same shared secret.

```lua
local ActiveSessions = {}

RegisterNetEvent('sigrdrifa:initiateHandshake', function(clientPublicKey)
    local _source = source
    
    -- Generate a unique KeyPair for this specific session
    local serverKeys = exports['sigrdrifa']:GenerateKeyPair()
    
    -- Derive the Shared Secret: (Server Private Key + Client Public Key)
    local sharedSecret = exports['sigrdrifa']:GetSharedSecret(serverKeys.privateKey, clientPublicKey)
    
    -- Store the secret mapped to the player's source ID
    ActiveSessions[_source] = sharedSecret
    
    -- Send the Server's Public Key back to the client
    TriggerClientEvent('sigrdrifa:finalizeHandshake', _source, serverKeys.publicKey)
end)

-- Cleanup session on disconnect
AddEventHandler('playerDropped', function()
    ActiveSessions[source] = nil
end)
```

---

### Why use Curve25519?

1. **No Static Passphrases**: There is no "hardcoded" password in your scripts that can be dumped or leaked.
2. **Perfect Forward Secrecy**: Every time a player connects, a new, unique secret is generated. If one session is compromised, others remain secure.
3. **Man-in-the-Middle Resistance**: Even if an attacker intercepts both Public Keys during transit, it is mathematically impossible to calculate the Shared Secret without possessing at least one of the Private Keys.
4. **Environment Isolation**: Private keys remain local to their environment (Client or Server) and are never exposed to the network.

⚠️ **WARNING**: Do **NOT** use Sigrdrifa to encrypt data intended for long-term storage (like SQL databases) using session keys. These keys change every startup and for every client. For persistent storage, use a static, server-side-only passphrase.

---

### Secure Data Transmission
Once the `secureSessionKey` is established, it can be passed directly into the encryption exports. The system automatically detects if you are using a string passphrase or a byte table key.

```lua
-- Client sending to Server
local encrypted = exports['sigrdrifa']:EncryptObject({item = "diamond", amount = 1}, secureSessionKey)
local b64 = exports['sigrdrifa']:ToBase64(encrypted)
TriggerServerEvent('inventory:secureDrop', b64)
```

---

## API Reference (Exports)

### Data Transformation & Utilities

Sigrdrifa provides specialized utilities to handle the transition between raw bytes and transportable formats.

| Function | Purpose |
| :--- | :--- |
| `ToBase64` | Converts encrypted bytes into a Base64 string. **Required** for sending data through FiveM Events to prevent data corruption. |
| `ToHex` | Converts bytes into a Hexadecimal string. Useful for logging and technical debugging. |
| `ToEscapedString` | Sanitizes binary data for console output. Replaces control characters (like new lines) with readable escapes (e.g., `\10`) to keep the console clean. |

#### Transformation Example
```lua
local encrypted = exports['sigrdrifa']:EncryptObject(data, key)

-- CORRECT: Send this to Server
local networkData = exports['sigrdrifa']:ToBase64(encrypted)

-- DEBUG: Print this to F8 Console
print("Raw Payload: " .. exports['sigrdrifa']:ToEscapedString(encrypted))
```

### Encryption & Decryption

- **EncryptObject**: Serializes any Lua object to JSON and encrypts it. Defaults to **SHA-256** if no algorithm is specified.
- **DecryptObject**: Decrypts the payload and returns the original Lua object. Features an **Iterative Engine** that automatically attempts all supported algorithms to find a match.

```lua
-- Syntax: exports['sigrdrifa']:EncryptObject(object, key, algorithm)
-- Syntax: exports['sigrdrifa']:DecryptObject(byteTable, key)
```

### Utility and Enums
- **GetAlgos**: Returns the `Encryption.Algos` enum table.
- **GenerateKeyPair**: Returns `{ privateKey, publicKey }`.
- **GetSharedSecret**: Returns the 32-byte shared secret table.

---

## Security Best Practices

1. **Algorithm Selection**: Use `BLAKE3` for high-frequency data to minimize CPU overhead.
2. **Network Transit**: **Always** use `ToBase64` before triggering events. Raw encrypted bytes contain null characters that will truncate or corrupt the event payload.
3. **Clean-up**: Always clear server-side session keys on `playerDropped` to prevent memory leaks.

---

## License
Distributed under the MIT License. Optimized for secure resource communication in complex FiveM environments.