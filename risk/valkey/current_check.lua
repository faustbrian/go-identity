-- Current exact-marker check only: no writes, repair, debit or TTL renewal.
local function unavailable() return {'unavailable', ''} end
if #KEYS ~= 1 or #ARGV ~= 1 or #KEYS[1] > 256 then return unavailable() end
local expected = publicationFields(ARGV[1], 'confirmed')
if not expected then return unavailable() end
-- Bound the value before GET; wrong types and missing state never get repaired.
if redis.call('TYPE', KEYS[1]).ok ~= 'string' or redis.call('STRLEN', KEYS[1]) > 384 then return unavailable() end
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return unavailable() end
local clock = redis.call('TIME')
local seconds, micros = publicationInteger(clock[1]), publicationInteger(clock[2])
if not seconds or not micros or micros > 999999 or seconds > math.floor((9007199254740991-3600000000-999999)/1000000) then return unavailable() end
local now = seconds*1000000+micros
if now >= tonumber(expected[5]) or now < tonumber(expected[9]) then return unavailable() end
return {'current', expected[6]}
