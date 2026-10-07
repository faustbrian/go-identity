-- Install or renew an exact recovery fence, never a healthy marker.
local exact, maximumLease = 9007199254740991, 60000000
local function unavailable() return {'unavailable', ''} end
local function decimal(v, maximum)
  if type(v) ~= 'string' or #v < 1 or #v > #maximum or not string.match(v, '^%d+$') or (#v > 1 and string.sub(v, 1, 1) == '0') then return false end
  return #v < #maximum or v <= maximum
end
local function greater(a, b) return #a > #b or (#a == #b and a > b) end
local function marker(value)
  if type(value) ~= 'string' or #value > 128 then return nil end
  local fields = {}
  for field in string.gmatch(value .. '|', '(.-)|') do
    if #fields == 5 then return nil end
    fields[#fields+1] = field
  end
  if #fields ~= 5 or fields[1] ~= 'replaying' then return nil end
  for _, i in ipairs({2,4}) do
    if #fields[i] ~= 32 or not string.match(fields[i], '^[0-9a-f]+$') or fields[i] == string.rep('0',32) then return nil end
  end
  if not decimal(fields[3], '18446744073709551615') or fields[3] == '0' or not decimal(fields[5], '9007199254740991') then return nil end
  return fields
end
if #KEYS ~= 1 or #KEYS[1] > 256 or #ARGV ~= 2 then return unavailable() end
local candidate = marker(ARGV[2])
local previous = nil
if ARGV[1] ~= '' then previous = marker(ARGV[1]); if not previous then return unavailable() end end
if not candidate then return unavailable() end
local clock = redis.call('TIME')
if not decimal(clock[1], '9007199254740991') or not decimal(clock[2], '999999') then return unavailable() end
local seconds, micros = tonumber(clock[1]), tonumber(clock[2])
if seconds > math.floor((exact-maximumLease-999999)/1000000) then return unavailable() end
local now, expires = seconds*1000000+micros, tonumber(candidate[5])
if expires <= now or expires > now+maximumLease then return unavailable() end
local kind = redis.call('TYPE', KEYS[1]).ok
if kind ~= 'none' and kind ~= 'string' then return unavailable() end
local current = nil
if kind == 'string' then
  if redis.call('STRLEN', KEYS[1]) > 128 then return unavailable() end
  local value = redis.call('GET', KEYS[1])
  current = marker(value)
  if not current then return unavailable() end
  if value == ARGV[2] then return {'fenced', ARGV[2]} end
  if value ~= ARGV[1] then return unavailable() end
elseif previous and tonumber(previous[5]) > now then
  -- A disappeared live fence means reset/eviction, not renewal permission.
  return unavailable()
end
if previous then
  if candidate[3] == previous[3] then
    if candidate[2] ~= previous[2] or candidate[4] ~= previous[4] or tonumber(previous[5]) <= now or expires <= tonumber(previous[5]) then return unavailable() end
  elseif not greater(candidate[3], previous[3]) or tonumber(previous[5]) > now then
    return unavailable()
  end
elseif current then
  return unavailable()
end
-- One write assigns both custody and expiry. Logical microsecond expiry is
-- still checked by every recovery effect, independent of physical rounding.
redis.call('SET', KEYS[1], ARGV[2], 'PXAT', string.format('%.0f', math.ceil(expires/1000)))
return {'fenced', ARGV[2]}
