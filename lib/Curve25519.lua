--[[
    Curve25519 Implementation for FiveM (Lua)
    Ported from C# FxEvents.Shared.Encryption
    
    Credits:
    - FiveM C# adaptation by manups4e
    - Original C# Port by Hans Wolff
    - Java Port by Dmitry Skiba
    - C implementation by Matthijs van Duin
]]

local Curve25519Inner = {}

-- Constant Data
local Order = {237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}
local P25 = 33554431 -- (1 << 25) - 1
local P26 = 67108863 -- (1 << 26) - 1

--- Helper: Create a Long10 structure for GF(2^255-19) math
local function CreateLong10(n0, n1, n2, n3, n4, n5, n6, n7, n8, n9)
    return {
        N0 = n0 or 0, N1 = n1 or 0, N2 = n2 or 0, N3 = n3 or 0, N4 = n4 or 0,
        N5 = n5 or 0, N6 = n6 or 0, N7 = n7 or 0, N8 = n8 or 0, N9 = n9 or 0
    }
end

--- Clamp private key bits to make it a valid Curve25519 scalar
function Curve25519Inner.ClampPrivateKeyInline(key)
    key[32] = (key[32] & 0x7F) | 0x40
    key[1] = key[1] & 0xF8
end

--- Generate 32 random bytes and clamp them
function Curve25519Inner.CreateRandomPrivateKey()
    local key = {}
    for i = 1, 32 do
        key[i] = math.random(0, 255)
    end
    Curve25519Inner.ClampPrivateKeyInline(key)
    return key
end

-------------------------------------------------------------------------------
-- Radix 2^25.5 GF(2^255-19) Mathematics
-------------------------------------------------------------------------------

--- Unpack little-endian byte format into internal Long10 format
local function Unpack(x, m)
    x.N0 = (m[1] & 0xFF) | (m[2] & 0xFF) << 8 | (m[3] & 0xFF) << 16 | ((m[4] & 0xFF) & 3) << 24
    x.N1 = ((m[4] & 0xFF) & 0xFC) >> 2 | (m[5] & 0xFF) << 6 | (m[6] & 0xFF) << 14 | ((m[7] & 0xFF) & 7) << 22
    x.N2 = ((m[7] & 0xFF) & 0xF8) >> 3 | (m[8] & 0xFF) << 5 | (m[9] & 0xFF) << 13 | ((m[10] & 0xFF) & 31) << 21
    x.N3 = ((m[10] & 0xFF) & 0xE0) >> 5 | (m[11] & 0xFF) << 3 | (m[12] & 0xFF) << 11 | ((m[13] & 0xFF) & 63) << 19
    x.N4 = ((m[13] & 0xFF) & 0xC0) >> 6 | (m[14] & 0xFF) << 2 | (m[15] & 0xFF) << 10 | (m[16] & 0xFF) << 18
    x.N5 = (m[17] & 0xFF) | (m[18] & 0xFF) << 8 | (m[19] & 0xFF) << 16 | ((m[20] & 0xFF) & 1) << 24
    x.N6 = ((m[20] & 0xFF) & 0xFE) >> 1 | (m[21] & 0xFF) << 7 | (m[22] & 0xFF) << 15 | ((m[23] & 0xFF) & 7) << 23
    x.N7 = ((m[23] & 0xFF) & 0xF8) >> 3 | (m[24] & 0xFF) << 5 | (m[25] & 0xFF) << 13 | ((m[26] & 0xFF) & 15) << 21
    x.N8 = ((m[26] & 0xFF) & 0xF0) >> 4 | (m[27] & 0xFF) << 4 | (m[28] & 0xFF) << 12 | ((m[29] & 0xFF) & 63) << 20
    x.N9 = ((m[29] & 0xFF) & 0xC0) >> 6 | (m[30] & 0xFF) << 2 | (m[31] & 0xFF) << 10 | (m[32] & 0xFF) << 18
end

--- Pack internal Long10 format back into little-endian bytes
local function Pack(x, m)
    local function isOverflow(v)
        return ((v.N0 > P26 - 19) and (v.N1 & v.N3 & v.N5 & v.N7 & v.N9 == P25) and (v.N2 & v.N4 & v.N6 & v.N8 == P26)) or (v.N9 > P25)
    end
    
    local ld = (isOverflow(x) and 1 or 0) - (x.N9 < 0 and 1 or 0)
    local ud = ld * -(P25 + 1)
    ld = ld * 19
    
    local t = ld + x.N0 + (x.N1 << 26)
    m[1] = t & 0xFF; m[2] = (t >> 8) & 0xFF; m[3] = (t >> 16) & 0xFF; m[4] = (t >> 24) & 0xFF
    t = (t >> 32) + (x.N2 << 19)
    m[5] = t & 0xFF; m[6] = (t >> 8) & 0xFF; m[7] = (t >> 16) & 0xFF; m[8] = (t >> 24) & 0xFF
    t = (t >> 32) + (x.N3 << 13)
    m[9] = t & 0xFF; m[10] = (t >> 8) & 0xFF; m[11] = (t >> 16) & 0xFF; m[12] = (t >> 24) & 0xFF
    t = (t >> 32) + (x.N4 << 6)
    m[13] = t & 0xFF; m[14] = (t >> 8) & 0xFF; m[15] = (t >> 16) & 0xFF; m[16] = (t >> 24) & 0xFF
    t = (t >> 32) + x.N5 + (x.N6 << 25)
    m[17] = t & 0xFF; m[18] = (t >> 8) & 0xFF; m[19] = (t >> 16) & 0xFF; m[20] = (t >> 24) & 0xFF
    t = (t >> 32) + (x.N7 << 19)
    m[21] = t & 0xFF; m[22] = (t >> 8) & 0xFF; m[23] = (t >> 16) & 0xFF; m[24] = (t >> 24) & 0xFF
    t = (t >> 32) + (x.N8 << 12)
    m[25] = t & 0xFF; m[26] = (t >> 8) & 0xFF; m[27] = (t >> 16) & 0xFF; m[28] = (t >> 24) & 0xFF
    t = (t >> 32) + ((x.N9 + ud) << 6)
    m[29] = t & 0xFF; m[30] = (t >> 8) & 0xFF; m[31] = (t >> 16) & 0xFF; m[32] = (t >> 24) & 0xFF
end

--- Add two numbers in GF(2^255-19)
local function Add(xy, x, y)
    xy.N0 = x.N0 + y.N0; xy.N1 = x.N1 + y.N1; xy.N2 = x.N2 + y.N2; xy.N3 = x.N3 + y.N3; xy.N4 = x.N4 + y.N4
    xy.N5 = x.N5 + y.N5; xy.N6 = x.N6 + y.N6; xy.N7 = x.N7 + y.N7; xy.N8 = x.N8 + y.N8; xy.N9 = x.N9 + y.N9
end

--- Subtract two numbers in GF(2^255-19)
local function Sub(xy, x, y)
    xy.N0 = x.N0 - y.N0; xy.N1 = x.N1 - y.N1; xy.N2 = x.N2 - y.N2; xy.N3 = x.N3 - y.N3; xy.N4 = x.N4 - y.N4
    xy.N5 = x.N5 - y.N5; xy.N6 = x.N6 - y.N6; xy.N7 = x.N7 - y.N7; xy.N8 = x.N8 - y.N8; xy.N9 = x.N9 - y.N9
end

--- Multiply two numbers in GF(2^255-19)
local function Multiply(xy, x, y)
    local x0, x1, x2, x3, x4, x5, x6, x7, x8, x9 = x.N0, x.N1, x.N2, x.N3, x.N4, x.N5, x.N6, x.N7, x.N8, x.N9
    local y0, y1, y2, y3, y4, y5, y6, y7, y8, y9 = y.N0, y.N1, y.N2, y.N3, y.N4, y.N5, y.N6, y.N7, y.N8, y.N9
    
    local t = (x0 * y8) + (x2 * y6) + (x4 * y4) + (x6 * y2) + (x8 * y0) + 2 * ((x1 * y7) + (x3 * y5) + (x5 * y3) + (x7 * y1)) + 38 * (x9 * y9)
    xy.N8 = t & 0x3FFFFFF
    t = (t >> 26) + (x0 * y9) + (x1 * y8) + (x2 * y7) + (x3 * y6) + (x4 * y5) + (x5 * y4) + (x6 * y3) + (x7 * y2) + (x8 * y1) + (x9 * y0)
    xy.N9 = t & 0x1FFFFFF
    t = (x0 * y0) + 19 * ((t >> 25) + (x2 * y8) + (x4 * y6) + (x6 * y4) + (x8 * y2)) + 38 * ((x1 * y9) + (x3 * y7) + (x5 * y5) + (x7 * y3) + (x9 * y1))
    xy.N0 = t & 0x3FFFFFF
    t = (t >> 26) + (x0 * y1) + (x1 * y0) + 19 * ((x2 * y9) + (x3 * y8) + (x4 * y7) + (x5 * y6) + (x6 * y5) + (x7 * y4) + (x8 * y3) + (x9 * y2))
    xy.N1 = t & 0x1FFFFFF
    t = (t >> 25) + (x0 * y2) + (x2 * y0) + 19 * ((x4 * y8) + (x6 * y6) + (x8 * y4)) + 2 * (x1 * y1) + 38 * ((x3 * y9) + (x5 * y7) + (x7 * y5) + (x9 * y3))
    xy.N2 = t & 0x3FFFFFF
    t = (t >> 26) + (x0 * y3) + (x1 * y2) + (x2 * y1) + (x3 * y0) + 19 * ((x4 * y9) + (x5 * y8) + (x6 * y7) + (x7 * y6) + (x8 * y5) + (x9 * y4))
    xy.N3 = t & 0x1FFFFFF
    t = (t >> 25) + (x0 * y4) + (x2 * y2) + (x4 * y0) + 19 * ((x6 * y8) + (x8 * y6)) + 2 * ((x1 * y3) + (x3 * y1)) + 38 * ((x5 * y9) + (x7 * y7) + (x9 * y5))
    xy.N4 = t & 0x3FFFFFF
    t = (t >> 26) + (x0 * y5) + (x1 * y4) + (x2 * y3) + (x3 * y2) + (x4 * y1) + (x5 * y0) + 19 * ((x6 * y9) + (x7 * y8) + (x8 * y7) + (x9 * y6))
    xy.N5 = t & 0x1FFFFFF
    t = (t >> 25) + (x0 * y6) + (x2 * y4) + (x4 * y2) + (x6 * y0) + 19 * (x8 * y8) + 2 * ((x1 * y5) + (x3 * y3) + (x5 * y1)) + 38 * ((x7 * y9) + (x9 * y7))
    xy.N6 = t & 0x3FFFFFF
    t = (t >> 26) + (x0 * y7) + (x1 * y6) + (x2 * y5) + (x3 * y4) + (x4 * y3) + (x5 * y2) + (x6 * y1) + (x7 * y0) + 19 * ((x8 * y9) + (x9 * y8))
    xy.N7 = t & 0x1FFFFFF
    t = (t >> 25) + xy.N8
    xy.N8 = t & 0x3FFFFFF
    xy.N9 = xy.N9 + (t >> 26)
end

--- Square a number: Optimization of Multiply(x, x)
local function Square(xsqr, x)
    Multiply(xsqr, x, x)
end

--- Calculate reciprocal using Fermat's Little Theorem: y = x^(p-2)
local function Reciprocal(y, x, sqrtAssist)
    local t0, t1, t2, t3, t4 = CreateLong10(), CreateLong10(), CreateLong10(), CreateLong10(), CreateLong10()
    Square(t1, x); Square(t2, t1); Square(t0, t2); Multiply(t2, t0, x); Multiply(t0, t2, t1)
    Square(t1, t0); Multiply(t3, t1, t2); Square(t1, t3); Square(t2, t1); Square(t1, t2); Square(t2, t1)
    Square(t1, t2); Multiply(t2, t1, t3); Square(t1, t2); Square(t3, t1)
    for i = 1, 4 do Square(t1, t3); Square(t3, t1) end
    Multiply(t1, t3, t2); Square(t3, t1); Square(t4, t3)
    for i = 1, 9 do Square(t3, t4); Square(t4, t3) end
    Multiply(t3, t4, t1)
    for i = 1, 5 do Square(t1, t3); Square(t3, t1) end
    Multiply(t1, t3, t2); Square(t2, t1); Square(t3, t2)
    for i = 1, 24 do Square(t2, t3); Square(t3, t2) end
    Multiply(t2, t3, t1); Square(t3, t2); Square(t4, t3)
    for i = 1, 49 do Square(t3, t4); Square(t4, t3) end
    Multiply(t3, t4, t2)
    for i = 1, 25 do Square(t4, t3); Square(t3, t4) end
    Multiply(t2, t3, t1); Square(t1, t2); Square(t2, t1)
    if sqrtAssist then Multiply(y, x, t2) else Square(t1, t2); Square(t2, t1); Square(t1, t2); Multiply(y, t1, t0) end
end

-------------------------------------------------------------------------------
-- Montgomery Ladder for Point Multiplication
-------------------------------------------------------------------------------

local function MontyPrepare(t1, t2, ax, az)
    Add(t1, ax, az); Sub(t2, ax, az)
end

local function MontyAdd(t1, t2, t3, t4, ax, az, dx)
    Multiply(ax, t2, t3); Multiply(az, t1, t4)
    Add(t1, ax, az); Sub(t2, ax, az)
    Square(ax, t1); Square(t1, t2)
    Multiply(az, t1, dx)
end

local function MontyDouble(t1, t2, t3, t4, bx, bz)
    Square(t1, t3); Square(t2, t4)
    Multiply(bx, t1, t2); Sub(t2, t1, t2)
    local temp = CreateLong10(); Multiply(temp, t2, CreateLong10(121665)) -- a24 = (486662-2)/4
    Add(t1, t1, temp); Multiply(bz, t1, t2)
end

--- Core Curve25519 DH Function
function Curve25519Inner.Core(publicKey, signingKey, privateKey, peerPublicKey)
    local dx, t1, t2, t3, t4 = CreateLong10(), CreateLong10(), CreateLong10(), CreateLong10(), CreateLong10()
    local x = { CreateLong10(1), CreateLong10() }
    local z = { CreateLong10(0), CreateLong10(1) }

    if peerPublicKey then Unpack(dx, peerPublicKey) else dx.N0 = 9 end

    -- Initialize 1G
    x[2].N0 = dx.N0; x[2].N1 = dx.N1; x[2].N2 = dx.N2; x[2].N3 = dx.N3; x[2].N4 = dx.N4
    x[2].N5 = dx.N5; x[2].N6 = dx.N6; x[2].N7 = dx.N7; x[2].N8 = dx.N8; x[2].N9 = dx.N9

    -- Montgomery Ladder Loop
    for i = 32, 1, -1 do
        local byte = privateKey[i] & 0xFF
        for j = 7, 0, -1 do
            local bit = (byte >> j) & 1
            local sel = bit + 1
            local alt = 2 - bit
            
            MontyPrepare(t1, t2, x[alt], z[alt])
            MontyPrepare(t3, t4, x[sel], z[sel])
            MontyAdd(t1, t2, t3, t4, x[alt], z[alt], dx)
            MontyDouble(t1, t2, t3, t4, x[sel], z[sel])
        end
    end

    Reciprocal(t1, z[1], false)
    Multiply(dx, x[1], t1)
    Pack(dx, publicKey)
end

-------------------------------------------------------------------------------
-- Public API
-------------------------------------------------------------------------------

Curve25519 = {}
Curve25519.__index = Curve25519

--- Factory to create the Curve25519 instance
function Curve25519.Create()
    local self = setmetatable({}, Curve25519)
    self._privateKey = nil
    return self
end

--- Get or generate the Public Key
function Curve25519:GetPublicKey()
    if not self._privateKey then self._privateKey = Curve25519Inner.CreateRandomPrivateKey() end
    local pub = {}
    Curve25519Inner.Core(pub, nil, self._privateKey, nil)
    return pub
end

--- Get Shared Secret with another party's public key
function Curve25519:GetSharedSecret(otherPublicKey)
    if not self._privateKey then self._privateKey = Curve25519Inner.CreateRandomPrivateKey() end
    local secret = {}
    Curve25519Inner.Core(secret, nil, self._privateKey, otherPublicKey)
    return secret
end

--- Manually set the Private Key
function Curve25519:FromPrivateKey(keyTable)
    self._privateKey = keyTable
end