--[[
    =====================================================================
    ENCRYPTION.LUA - FiveM Edition (Enum Version)
    Taken from FXEvents and ported to Lua by manups4e
    =====================================================================
]]

Encryption = {}

-- Recovery of the SHA module via Getter
local crypto = GetShaObject()
local MAGIC_MARKER = "FX!"

-- ENUM for Algorithms
Encryption.Algos = {
    -- Classic
    MD5      = "md5",
    SHA1     = "sha1",

    -- SHA-2 (Standard)
    SHA224   = "sha224",
    SHA256   = "sha256",
    SHA384   = "sha384",
    SHA512   = "sha512",

    -- SHA-3 (Modern & Ultra-Secure)
    SHA3_256 = "sha3_256",
    SHA3_512 = "sha3_512",

    -- BLAKE (High Performance)
    BLAKE2B  = "blake2b",
    BLAKE3   = "blake3", -- Highly suggested as it appears to be the most performant on FiveM
}
math.randomseed(GetGameTimer())

-------------------------------------------------------------------------------
-- 1. INTERNAL HELPERS
-------------------------------------------------------------------------------

--- Generates a hash byte table using the specified algorithm
function Encryption.GenerateHash(input, algo)
    -- Use the enum value or default to SHA256
    algo = algo or Encryption.Algos.SHA256

    if not crypto or not crypto[algo] then
        print("^1[Encryption] Error: Algorithm '" .. tostring(algo) .. "' not supported!^7")
        return nil
    end

    local binaryString = crypto[algo](input)
    local byteTable = {}
    for i = 1, #binaryString do
        byteTable[i] = string.byte(binaryString, i)
    end

    return byteTable
end

-------------------------------------------------------------------------------
-- 2. CORE OBJECT ENCRYPTION
-------------------------------------------------------------------------------

--- Encrypts any Lua object
function Encryption.EncryptObject(obj, key, algo)
    if obj == nil then return nil end
    assert(key ~= nil and #key > 3,
        "^1[Encryption] EncryptObject Error: encryption key can't be null or shorter than 3 characters")
    algo = algo or Encryption.Algos.SHA256

    local jsonStr = json.encode(obj)
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

--- Decrypts and validates integrity
function Encryption.DecryptObject(encryptedData, key, forceAlgo)
    if not encryptedData or #encryptedData == 0 then
        return nil, "EMPTY_DATA"
    end
    assert(key ~= nil and #key > 3,
        "^1[Encryption] DecryptObject Error: encryption key can't be null or shorter than 3 characters")

    -- Use the Enum for the retry list
    local algosToTry = forceAlgo and { forceAlgo } or {
        Encryption.Algos.BLAKE3,
        Encryption.Algos.SHA256,
        Encryption.Algos.SHA512,
        Encryption.Algos.SHA3_256,
        Encryption.Algos.MD5,
        Encryption.Algos.SHA1,
        Encryption.Algos.SHA224,
        Encryption.Algos.SHA384,
        Encryption.Algos.SHA3_512,
        Encryption.Algos.BLAKE2B,
    }

    for _, algo in ipairs(algosToTry) do
        local keyBytes = type(key) == "string" and Encryption.GenerateHash(key, algo) or key
        if not keyBytes then goto next_algo end

        local decryptedChars = {}
        for i = 1, #encryptedData do
            local keyByte = keyBytes[((i - 1) % #keyBytes) + 1]
            decryptedChars[i] = string.char(encryptedData[i] ~ keyByte)
        end

        local fullStr = table.concat(decryptedChars)

        if fullStr:sub(1, #MAGIC_MARKER) == MAGIC_MARKER then
            local headerEnd = fullStr:find("|")
            if headerEnd then
                local jsonStr = fullStr:sub(headerEnd + 1)
                local success, result = pcall(json.decode, jsonStr)
                if success then return result, nil end
            end
        end

        ::next_algo::
    end

    return nil, "INVALID_KEY_OR_ALGO"
end

-------------------------------------------------------------------------------
-- 3. UTILITIES
-------------------------------------------------------------------------------

function Encryption.ToHex(bytes, separator)
    separator = separator or ""
    local hex = {}
    for i = 1, #bytes do table.insert(hex, string.format("%02X", bytes[i])) end
    return table.concat(hex, separator)
end

function Encryption.ToBase64(bytes)
    -- We use our binary string helper before passing to the library's base64
    local binStr = Encryption.BytesToBinaryString(bytes)
    return crypto.bin_to_base64(binStr)
end

--- Converts a byte table to a binary string
function Encryption.BytesToBinaryString(bytes)
    local result = {}
    for i = 1, #bytes do
        local b = bytes[i]
        if b >= 32 and b <= 126 then
            table.insert(result, string.char(b)) -- Carattere normale
        else
            -- Workaround to avoid escaping and special chars to mess the print / value of the string
            table.insert(result, "\\" .. b)
        end
    end
    return table.concat(result)
end
