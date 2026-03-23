-------------------------------------------------------------------------------
-- S I G R D R Í F A   C U R V E 2 5 5 1 9   E X P O R T S
-- Advanced Elliptic Curve Diffie-Hellman (ECDH) logic
-------------------------------------------------------------------------------

--- Generates a new Curve25519 KeyPair for the caller
-- This creates a temporary instance, generates keys, and returns them as byte tables.
-- @return table: { privateKey = byte[], publicKey = byte[] }
exports('GenerateKeyPair', function()
    return Encryption.GenerateKeyPair()
end)

--- Calculates a Shared Secret using a Private Key and a Remote Public Key
-- @param privateKey table: The byte array of your local private key
-- @param remotePublicKey table: The byte array of the received public key
-- @return table: The shared secret byte array (32 bytes)
exports('GetSharedSecret', function(privateKey, remotePublicKey)
    return Encryption.GetSharedSecret(privateKey, remotePublicKey)
end)

-------------------------------------------------------------------------------
-- S I G R D R Í F A   F I V E M   E X P O R T S
-- Official Valkyrie Release - Secure Logic Bridge
-------------------------------------------------------------------------------

--- Returns the table of supported algorithms (Enum)
-- Use this to avoid string typos in other scripts.
--- @return table { SHA256, SHA512, MD5, etc. }
exports('GetAlgos', function()
    return Encryption.Algos
end)

--- Generates a hash from the input string
--- @param input string: The text to be hashed
--- @param algo string: The algorithm from Encryption.Algos
--- @return table: An array of bytes representing the hash
exports('Hash', function(input, algo)
    return Encryption.GenerateHash(input, algo)
end)

--- Encrypts any Lua object into a byte array
-- Supports tables, strings, numbers, and booleans.
--- @param obj any: The data to protect
--- @param key string/table: The passphrase or shared secret
--- @param algo string: (Optional) Hash algorithm for key derivation
--- @return table: Encrypted byte array
exports('Encrypt', function(obj, key, algo)
    return Encryption.EncryptObject(obj, key, algo)
end)

--- Decrypts a byte array back to its original Lua object automatically and validates the Magic Marker and JSON integrity.
---- @param encryptedData any: The array of encrypted bytes
---- @param key string: The decryption key
---- @param forceAlgo string: (Optional) Specifically force an algorithm
---- @return any: The original data, or nil if decryption failed
exports('Decrypt', function(encryptedData, key, forceAlgo)
    return Encryption.DecryptObject(encryptedData, key, forceAlgo)
end)

--- Generates a random Valkyrie-themed passphrase
-- Useful for creating temporary session keys.
--- @return string: A random word-based passphrase
exports('GeneratePassphrase', function()
    return Encryption.GenerateKey()
end)

--- Converts a byte array to a Base64 string
-- Crucial for sending encrypted data via TriggerServerEvent/TriggerClientEvent
--- @param bytes table: The byte array
--- @return string: Base64 encoded string
exports('ToBase64', function(bytes)
    return Encryption.ToBase64(bytes)
end)

--- Converts a byte array to a Hexadecimal string
-- Primarily used for debugging and logging.
--- @param bytes table: The byte array
--- @param separator string: (Optional) e.g., " " or ":"
--- @return string: Hex encoded string
exports('ToHex', function(bytes, separator)
    return Encryption.ToHex(bytes, separator)
end)

--- Converts a byte array to an Escaped String
-- Replaces control characters (like \n) with visible text for console printing.
--- @param bytes table: The byte array
--- @return string: Safe-to-print string
exports('BytesToBinaryString', function(bytes)
    return Encryption.BytesToBinaryString(bytes)
end)