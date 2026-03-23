--[[
    ============================================================
    S I G R D R Í F A  -  TEST SUITE
    ============================================================
    This script performs automated unit tests on the 
    Sigrdrífa encryption library.
    ============================================================
]]

local function RunSigrdrifaTests()
    print("^3[Sigrdrífa:Test] Starting Valkyrie Trials...^7")
    
    local testKey = "Valkyrie-Secret-Passphrase-2026"
    local successCount = 0
    local totalTests = 5

    ---------------------------------------------------------------------------
    -- TEST 1: Table Encryption & Decryption
    ---------------------------------------------------------------------------
    local tableData = { id = 1, name = "Sigurd", gear = {"Sword", "Shield"}, power = 9001 }
    local encTable = Encryption.EncryptObject(tableData, testKey, Encryption.Algos.SHA256)
    local decTable = Encryption.DecryptObject(encTable, testKey)

    if decTable and decTable.name == "Sigurd" and decTable.gear[1] == "Sword" then
        print("^2[PASS]^7 Test 1: Complex Table Integrity")
        successCount = successCount + 1
    else
        print("^1[FAIL]^7 Test 1: Complex Table Integrity")
    end

    ---------------------------------------------------------------------------
    -- TEST 2: String & Number Encryption
    ---------------------------------------------------------------------------
    local stringData = "Valhalla awaits the brave"
    local encString = Encryption.EncryptObject(stringData, testKey, Encryption.Algos.BLAKE3)
    local decString = Encryption.DecryptObject(encString, testKey, Encryption.Algos.BLAKE3)

    if decString == stringData then
        print("^2[PASS]^7 Test 2: Simple String (using BLAKE3)")
        successCount = successCount + 1
    else
        print("^1[FAIL]^7 Test 2: Simple String")
    end

    ---------------------------------------------------------------------------
    -- TEST 3: Wrong Key Management
    ---------------------------------------------------------------------------
    local secretMessage = "Hidden Treasure Location"
    local encSecret = Encryption.EncryptObject(secretMessage, testKey)
    local decSecret, err = Encryption.DecryptObject(encSecret, "WRONG_KEY")

    if decSecret == nil and err == "INVALID_KEY_OR_ALGO" then
        print("^2[PASS]^7 Test 3: Security - Rejection of Wrong Key")
        successCount = successCount + 1
    else
        print("^1[FAIL]^7 Test 3: Security - System accepted a wrong key!")
    end

    ---------------------------------------------------------------------------
    -- TEST 4: Algorithm Mismatch Protection
    ---------------------------------------------------------------------------
    -- Encrypt with SHA512, try to force decrypt with MD5
    local enc512 = Encryption.EncryptObject("Data", testKey, Encryption.Algos.SHA512)
    local decMismatch, errMismatch = Encryption.DecryptObject(enc512, testKey, Encryption.Algos.MD5)

    if decMismatch == nil then
        print("^2[PASS]^7 Test 4: Security - Algorithm Mismatch Protection")
        successCount = successCount + 1
    else
        print("^1[FAIL]^7 Test 4: Security - Decrypted with wrong algorithm!")
    end

    ---------------------------------------------------------------------------
    -- TEST 5: Base64 & Hex Utilities
    ---------------------------------------------------------------------------
    local rawData = { test = true }
    local encrypted = Encryption.EncryptObject(rawData, testKey)
    local b64 = Encryption.ToBase64(encrypted)
    local hex = Encryption.ToHex(encrypted)

    if type(b64) == "string" and #b64 > 0 and type(hex) == "string" then
        print("^2[PASS]^7 Test 5: Utilities (Base64 & Hex)")
        successCount = successCount + 1
    else
        print("^1[FAIL]^7 Test 5: Utilities")
    end

    ---------------------------------------------------------------------------
    -- FINAL RESULTS
    ---------------------------------------------------------------------------
    print("------------------------------------------------------------")
    if successCount == totalTests then
        print("^2[SIGRDRÍFA READY]^7 All " .. successCount .. "/" .. totalTests .. " trials passed. The Bifröst is secure.")
    else
        print("^1[SIGRDRÍFA FAILED]^7 Only " .. successCount .. "/" .. totalTests .. " trials passed. Check logic.")
    end
    print("------------------------------------------------------------")
end

-- Command to run tests manually in console
RegisterCommand('test_sigrdrifa', function()
    RunSigrdrifaTests()
end, false)

-- -- Also run once on script start
-- Citizen.CreateThread(function()
--     Citizen.Wait(1000)
--     RunSigrdrifaTests()
-- end)