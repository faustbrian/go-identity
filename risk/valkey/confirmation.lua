-- Recorded primary confirmation is not public health or counter continuity.
local function unavailable() return {'unavailable', ''} end
if #KEYS ~= 1 or type(KEYS[1]) ~= 'string' or #KEYS[1] > 256 or #ARGV ~= 2 then return unavailable() end
local fields = publicationFields(ARGV[2], 'confirmed', nil)
if not fields or ARGV[1] ~= 'published|' .. table.concat(fields, '|', 2, 11) then return unavailable() end
local clock = redis.call('TIME')
local seconds, micros = publicationInteger(clock[1]), publicationInteger(clock[2])
if not seconds or not micros or micros > 999999 or seconds > math.floor((9007199254740991-60000000-999999)/1000000) then return unavailable() end
local now, expires = seconds*1000000+micros, tonumber(fields[5])
if expires <= now or expires > now+60000000 or tonumber(fields[9]) > now then return unavailable() end
if redis.call('TYPE', KEYS[1]).ok ~= 'string' or redis.call('STRLEN', KEYS[1]) > 384 then return unavailable() end
local current = redis.call('GET', KEYS[1])
if current == ARGV[2] then return {'confirmed', fields[6]} end
if current ~= ARGV[1] then return unavailable() end
redis.call('SET', KEYS[1], ARGV[2], 'PXAT', string.format('%.0f', math.ceil(expires/1000)))
return {'confirmed', fields[6]}
