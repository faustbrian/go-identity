-- Native fixed-window debit; no durable lockout or health authority.
local exact, horizon, probes = 9007199254740991, 3600000000, 8
local function integer(v)
  if type(v) ~= 'string' or #v < 1 or #v > 16 or not string.match(v, '^%d+$') or (#v > 1 and string.sub(v, 1, 1) == '0') then return nil end
  local n = tonumber(v)
  if not n or n > exact then return nil end
  return n
end
local function text(n) return string.format('%.0f', n) end
local function split(v, maximum)
  local parts = {}
  for part in string.gmatch(v .. '|', '(.-)|') do
    if #parts >= maximum then return nil end
    parts[#parts+1] = part
  end
  return parts
end
local epoch, fingerprint = ARGV[1], ARGV[2]
if type(epoch) ~= 'string' or #epoch ~= 32 or not string.match(epoch, '^[0-9a-f]+$') or type(fingerprint) ~= 'string' or #fingerprint ~= 64 or not string.match(fingerprint, '^[0-9a-f]+$') then return {'unknown', ''} end
local function unavailable() return {'unavailable', fingerprint} end
local window, dimensions, aliases = integer(ARGV[3]), integer(ARGV[4]), integer(ARGV[5])
if not window or window < 1 or window > horizon or not dimensions or dimensions < 1 or dimensions > 4 or not aliases or aliases < 1 or aliases > 4 or #KEYS ~= 2+probes+dimensions*aliases or #ARGV ~= 6+dimensions then return unavailable() end
for i = 1, dimensions do
  if type(ARGV[5+i]) ~= 'string' or #ARGV[5+i] < 1 or #ARGV[5+i] > 64 or string.find(ARGV[5+i], '|', 1, true) then return unavailable() end
end
local types = {}
for i, key in ipairs(KEYS) do
  if #key > 256 then return unavailable() end
  types[i] = redis.call('TYPE', key).ok
  if types[i] ~= 'none' and types[i] ~= 'string' then return unavailable() end
end
if types[1] ~= 'string' or redis.call('STRLEN', KEYS[1]) > 384 then return unavailable() end
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[6+dimensions] then return unavailable() end
local confirmed = publicationFields(current, 'confirmed', epoch)
if not confirmed then return unavailable() end
local clock = redis.call('TIME')
local seconds, micros = integer(clock[1]), integer(clock[2])
if not seconds or not micros or micros > 999999 or seconds > math.floor((exact-horizon-999999)/1000000) then return unavailable() end
local now = seconds*1000000+micros
if tonumber(confirmed[5]) <= now or tonumber(confirmed[9]) > now then return unavailable() end
local function record(key, limit, fields)
  if redis.call('STRLEN', key) > limit then return nil end
  local value = redis.call('GET', key)
  if not value then return nil end
  return split(value, fields)
end
-- Replay and expiry share one SET PXAT.
if types[2] == 'string' then
  local stored = record(KEYS[2], 2508, 3+dimensions*4+2)
  if not stored or #stored < 2 then return {'unknown', fingerprint} end
  if stored[1] ~= fingerprint then return {'not_committed', fingerprint} end
  if stored[2] ~= 'committed' or #stored ~= 3+dimensions*4+2 then return {'unknown', fingerprint} end
  local reply = {}
  for i = 3, #stored do reply[#reply+1] = stored[i] end
  return reply
end
local free = nil
-- Fixed probes bound live replay cardinality; exhaustion denies.
for i = 3, 2+probes do
  if types[i] == 'none' then
    if not free then free = KEYS[i] end
  else
    local entry = record(KEYS[i], 384, 3)
    if not entry or #entry ~= 3 or #entry[1] > 256 or #entry[2] ~= 64 or not string.match(entry[2], '^[0-9a-f]+$') then return unavailable() end
    local expires = integer(entry[3])
    if not expires or expires > now+horizon then return unavailable() end
    -- A reservation without replay acknowledgement may hide partial effects.
    if entry[1] == KEYS[2] then
      if entry[2] ~= fingerprint then return {'not_committed', fingerprint} end
      return {'unknown', fingerprint}
    end
    if expires <= now and not free then free = KEYS[i] end
  end
end
if not free then return unavailable() end
local states = {}
for i = 1, dimensions do
  local offset = 2+probes+(i-1)*aliases
  local root, rootIndex = nil, nil
  local records = {}
  for j = 1, aliases do
    local index = offset+j
    if types[index] == 'string' then
      local fields = record(KEYS[index], 384, 4)
      if not fields or (#fields ~= 2 and #fields ~= 4) or #fields[1] > 256 or (#fields == 2 and fields[2] ~= 'alias') then return unavailable() end
      if root and root ~= fields[1] then return unavailable() end
      root, records[index] = fields[1], fields
    end
  end
  if root then
    for j = 1, aliases do if KEYS[offset+j] == root then rootIndex = offset+j end end
    if not rootIndex or not records[rootIndex] or #records[rootIndex] ~= 4 then return unavailable() end
    for index, fields in pairs(records) do if index ~= rootIndex and #fields ~= 2 then return unavailable() end end
  else
    rootIndex = offset+aliases
    root = KEYS[rootIndex]
  end
  local start, count = now, 0
  if records[rootIndex] then
    local fields = records[rootIndex]
    start, count = integer(fields[2]), integer(fields[3])
    local storedWindow = integer(fields[4])
    if not start or not count or count < 1 or storedWindow ~= window or start > now or start > exact-window then return unavailable() end
    if now >= start+window then start, count = now, 0 end
  end
  if count >= exact then return unavailable() end
  states[i] = {root=root, offset=offset, start=start, count=count+1, expires=start+window}
end
-- All validation precedes the first write. Every allocation gains expiry
-- atomically, including on an error before the next command. No sorted index,
-- scan, or non-expiring intermediate record is created.
local replayExpiry = text(math.ceil((now+horizon)/1000))
redis.call('SET', free, KEYS[2] .. '|' .. fingerprint .. '|' .. text(now+horizon), 'PXAT', replayExpiry)
redis.call('SET', KEYS[2], fingerprint .. '|pending', 'PXAT', replayExpiry)
local reply = {'committed', fingerprint, text(now)}
for i, state in ipairs(states) do
  local expiry = text(math.ceil(state.expires/1000))
  redis.call('SET', state.root, state.root .. '|' .. text(state.start) .. '|' .. text(state.count) .. '|' .. text(window), 'PXAT', expiry)
  for j = 1, aliases do
    local key = KEYS[state.offset+j]
    if key ~= state.root then redis.call('SET', key, state.root .. '|alias', 'PXAT', expiry) end
  end
  reply[#reply+1] = ARGV[5+i]
  reply[#reply+1] = text(state.count)
  reply[#reply+1] = text(state.start)
  reply[#reply+1] = text(state.expires)
end
redis.call('SET', KEYS[2], fingerprint .. '|committed|' .. table.concat(reply, '|'), 'PXAT', replayExpiry)
return reply
