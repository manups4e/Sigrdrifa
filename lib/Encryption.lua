--[[
    =====================================================================
    SIGRDRÍFA ENCRYPTION SUITE - FiveM Edition
    Valkyrie Release: Advanced Cryptography & Performance
    =====================================================================
]]

Encryption = {}

-- Resource internal modules
local crypto = GetShaObject()
local chacha = GetChaCha20()
local MAGIC_MARKER = "FX!"

-- Algorithm Definitions
Encryption.Algos = {
    -- Stream Ciphers (High Performance)
    CHACHA20  = "chacha20",
    XCHACHA20 = "xchacha20", -- Recommended for FiveM networking

    -- Legacy Hashing (For XOR stream)
    MD5       = "md5",
    SHA1      = "sha1",

    -- SHA-2 Standard
    SHA224    = "sha224",
    SHA256    = "sha256",
    SHA384    = "sha384",
    SHA512    = "sha512",

    -- SHA-3 Modern
    SHA3_256  = "sha3_256",
    SHA3_512  = "sha3_512",

    -- BLAKE (Very fast hashing)
    BLAKE2B   = "blake2b",
    BLAKE3    = "blake3",
}

-- Initialize random seed with game timer and system time
math.randomseed(math.floor(GetGameTimer() * os.time()))

-------------------------------------------------------------------------------
-- 1. INTERNAL HELPERS
-------------------------------------------------------------------------------

--- Generates a hash byte table using the specified algorithm
function Encryption.GenerateHash(input, algo)
    algo = algo or Encryption.Algos.SHA256

    if not crypto or not crypto[algo] then
        print("^1[Sigrdrífa] Error: Algorithm '" .. tostring(algo) .. "' not supported!^7")
        return nil
    end

    local binaryString = crypto[algo](input)
    local byteTable = {}
    for i = 1, #binaryString do
        byteTable[i] = string.byte(binaryString, i)
    end

    return byteTable
end

--- Generates a random string for Nonces
local function getRandomString(length)
    local chars = {}
    for i = 1, length do
        chars[i] = string.char(math.random(0, 255))
    end
    return table.concat(chars)
end

-------------------------------------------------------------------------------
-- 2. ASYMMETRIC LOGIC (Curve25519)
-------------------------------------------------------------------------------

function Encryption.GenerateKeyPair()
    local curve = Curve25519.Create()
    local publicKey = curve:GetPublicKey()
    return {
        privateKey = curve._privateKey,
        publicKey = publicKey
    }
end

function Encryption.GetSharedSecret(privateKey, remotePublicKey)
    assert(type(privateKey) == "table", "Sigrdrífa: privateKey must be a byte table")
    assert(type(remotePublicKey) == "table", "Sigrdrífa: remotePublicKey must be a byte table")

    local curve = Curve25519.Create()
    curve:FromPrivateKey(privateKey)
    return curve:GetSharedSecret(remotePublicKey)
end

-------------------------------------------------------------------------------
-- 3. CORE ENCRYPTION ENGINE
-------------------------------------------------------------------------------

--- Encrypts any Lua object into a byte table
function Encryption.EncryptObject(obj, key, algo)
    if obj == nil or key == nil then return nil end
    if #key < 3 then return nil, "KEY_TOO_SHORT" end

    algo = algo or Encryption.Algos.SHA256
    local jsonStr = json.encode(obj)

    ---------------------------------------------------------------------------
    -- CHACHA20 / XCHACHA20 LOGIC
    ---------------------------------------------------------------------------
    if algo == Encryption.Algos.CHACHA20 or algo == Encryption.Algos.XCHACHA20 then
        -- FIXED: Ensure key is a 32-byte binary string for the library
        local binaryKey
        if type(key) == "string" then
            binaryKey = Encryption.BytesToBinaryString(Encryption.GenerateHash(key, Encryption.Algos.SHA256))
        else
            binaryKey = Encryption.BytesToBinaryString(key)
        end

        -- Final length validation to prevent library crashes
        if #binaryKey ~= 32 then binaryKey = Encryption.HexToBinaryString(binaryKey) end

        local nonceSize = (algo == Encryption.Algos.XCHACHA20) and 24 or 12
        local nonce = getRandomString(nonceSize)

        local encrypted
        if algo == Encryption.Algos.XCHACHA20 then
            encrypted = chacha.xchacha20_encrypt(binaryKey, 0, nonce, jsonStr)
        else
            encrypted = chacha.chacha20_encrypt(binaryKey, 0, nonce, jsonStr)
        end

        -- Structure: MAGIC + ALGO + | + NONCE + CIPHERTEXT
        local finalStr = MAGIC_MARKER .. algo .. "|" .. nonce .. encrypted
        return { string.byte(finalStr, 1, #finalStr) }
    end

    ---------------------------------------------------------------------------
    -- CLASSIC XOR LOGIC
    ---------------------------------------------------------------------------
    local payload = MAGIC_MARKER .. algo .. "|" .. jsonStr
    local dataBytes = { string.byte(payload, 1, #payload) }
    local keyBytes = type(key) == "string" and Encryption.GenerateHash(key, algo) or key

    local output = {}
    for i = 1, #dataBytes do
        local keyByte = keyBytes[((i - 1) % #keyBytes) + 1]
        output[i] = dataBytes[i] ~ keyByte
    end

    return output
end

--- Decrypts a byte array and validates its integrity
function Encryption.DecryptObject(encryptedData, key, forceAlgo)
    if not encryptedData or #encryptedData == 0 then return nil, "EMPTY_DATA" end
    if key == nil or #key < 3 then return nil, "INVALID_KEY" end

    -- Priority list for automatic algorithm detection
    local algosToTry = forceAlgo and { forceAlgo } or {
        Encryption.Algos.XCHACHA20,
        Encryption.Algos.CHACHA20,
        Encryption.Algos.BLAKE3,
        Encryption.Algos.SHA256,
        Encryption.Algos.SHA512
    }

    for _, algo in ipairs(algosToTry) do
        local decryptedStr = ""

        if algo == Encryption.Algos.XCHACHA20 or algo == Encryption.Algos.CHACHA20 then
            -------------------------------------------------------------------
            -- CHACHA20 DECRYPTION
            -------------------------------------------------------------------
            local fullBinary = Encryption.BytesToBinaryString(encryptedData)

            -- Prepare 32-byte binary key
            local binaryKey = type(key) == "string"
                and Encryption.BytesToBinaryString(Encryption.GenerateHash(key, Encryption.Algos.SHA256))
                or Encryption.BytesToBinaryString(key)

            if #binaryKey ~= 32 then binaryKey = Encryption.HexToBinaryString(binaryKey) end


            local expectedHeader = MAGIC_MARKER .. algo .. "|"
            local nonceSize = (algo == Encryption.Algos.XCHACHA20) and 24 or 12

            -- Slice Nonce and Ciphertext from the binary blob
            local startOffset = #expectedHeader + 1
            local nonce = fullBinary:sub(startOffset, startOffset + nonceSize - 1)
            local ciphertext = fullBinary:sub(startOffset + nonceSize)

            if #nonce == nonceSize and #binaryKey == 32 then
                if algo == Encryption.Algos.XCHACHA20 then
                    decryptedStr = chacha.xchacha20_decrypt(binaryKey, 0, nonce, ciphertext)
                else
                    decryptedStr = chacha.chacha20_decrypt(binaryKey, 0, nonce, ciphertext)
                end
            end
        else
            -------------------------------------------------------------------
            -- XOR DECRYPTION
            -------------------------------------------------------------------
            local keyBytes = type(key) == "string" and Encryption.GenerateHash(key, algo) or key
            local chars = {}
            for i = 1, #encryptedData do
                local keyByte = keyBytes[((i - 1) % #keyBytes) + 1]
                chars[i] = string.char(encryptedData[i] ~ keyByte)
            end
            decryptedStr = table.concat(chars)
        end

        -----------------------------------------------------------------------
        -- FINAL VALIDATION & JSON DECODING
        -----------------------------------------------------------------------
        if decryptedStr ~= "" then
            local jsonStr = ""
            local isValid = false

            -- CASE A: The algorithm is ChaCha20/XChaCha20
            -- We already checked the header outside, so decryptedStr IS the JSON.
            -- To verify the key, we check if the result is a VALID JSON string.
            if algo:find("chacha") then
                jsonStr = decryptedStr
                -- We use pcall to see if the decrypted "garbage" is actually valid JSON
                local success, result = pcall(json.decode, jsonStr)
                -- If it's valid JSON AND not a simple string/number (it should be our table)
                if success and type(result) == "table" then
                    return result, nil
                end

                -- CASE B: Classic XOR algorithms
                -- The Magic Marker MUST be at the beginning of the decrypted string.
            elseif decryptedStr:sub(1, #MAGIC_MARKER) == MAGIC_MARKER then
                local headerEnd = decryptedStr:find("|")
                if headerEnd then
                    jsonStr = decryptedStr:sub(headerEnd + 1)
                    local success, result = pcall(json.decode, jsonStr)
                    if success then return result, nil end
                end
            end
        end

        ::next_algo::
    end

    return nil, "INVALID_KEY_OR_ALGO"
end

-------------------------------------------------------------------------------
-- 4. UTILITIES
-------------------------------------------------------------------------------

function Encryption.ToHex(bytes, separator)
    separator = separator or ""
    local hex = {}
    for i = 1, #bytes do table.insert(hex, string.format("%02X", bytes[i])) end
    return table.concat(hex, separator)
end

function Encryption.ToBase64(bytes)
    local binStr = Encryption.BytesToBinaryString(bytes)
    return crypto.bin_to_base64(binStr)
end

function Encryption.BytesToBinaryString(bytes)
    local result = {}
    for i = 1, #bytes do
        result[i] = string.char(bytes[i])
    end
    return table.concat(result)
end

function Encryption.ToEscapedString(bytes)
    local result = {}
    for i = 1, #bytes do
        local b = bytes[i]
        if b >= 32 and b <= 126 then
            table.insert(result, string.char(b))
        else
            table.insert(result, "\\" .. b)
        end
    end
    return table.concat(result)
end

--- Converts a Hexadecimal string to a raw Binary string
-- This compresses a 64-char hex string back into 32 raw bytes.
function Encryption.HexToBinaryString(hex)
    return hex:gsub('..', function(cc)
        return string.char(tonumber(cc, 16))
    end)
end
