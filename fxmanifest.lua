fx_version 'cerulean'
game 'gta5'
author 'manups4e <manups4e@gmail.com>'
description "Sigrdrífa - Advanced Encryption Suite for FiveM"

--[[
    Named after the Valkyrie who revealed secrets of the runes, this suite safeguards your data's journey across the Bifröst of the network. Through the power of Curve25519 and high-speed hashing, it transforms raw data into protected runes, accessible only to those who hold the sacred shared secret.
    
    A robust, pure-Lua encryption wrapper ported from C#. Sigrdrífa provides a multi-algorithm hashing engine (SHA-2, SHA-3, BLAKE3) and Curve25519 key exchange. Designed for secure Client-Server communication with built-in magic-marker validation to prevent decryption artifacts and algorithm mismatch.
]]

version '1.0.0'

--[[  The script and its components were created by manups4e.
    Copying, modification, or distribution without permission is prohibited.
    All rights reserved.
    © 2026 manups4e
]]--

shared_scripts {
  "lib/sha2.lua",
  "lib/Curve25519.lua",
  "lib/Encryption.lua",
  "exports.lua",
  "encryption_test.lua"
}