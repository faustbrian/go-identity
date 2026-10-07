-- Restore one known committed snapshot under the exact live recovery fence.
-- This does not increment, advance journal progress or publish healthy state.
local exact, horizon, probes = 9007199254740991, 3600000000, 8
local function unavailable() return {'unavailable', ''} end
local function integer(v)
  if type(v) ~= 'string' or #v < 1 or #v > 16 or not string.match(v, '^%d+$') or (#v > 1 and string.sub(v,1,1) == '0') then return nil end
  local n = tonumber(v); if not n or n > exact then return nil end; return n
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
local marker, fingerprint = ARGV[1], ARGV[2]
if type(marker) ~= 'string' or #marker > 128 or type(fingerprint) ~= 'string' or #fingerprint ~= 64 or not string.match(fingerprint,'^[0-9a-f]+$') then return unavailable() end
local fence = split(marker,5)
if not fence or #fence ~= 5 or fence[1] ~= 'replaying' then return unavailable() end
for _, i in ipairs({2,4}) do
  if #fence[i] ~= 32 or not string.match(fence[i],'^[0-9a-f]+$') or fence[i] == string.rep('0',32) then return unavailable() end
end
local generation = fence[3]
if #generation < 1 or #generation > 20 or not string.match(generation,'^[1-9]%d*$') or (#generation == 20 and generation > '18446744073709551615') then return unavailable() end
local expires = integer(fence[5])
local window, dimensions, aliases, observed = integer(ARGV[3]),integer(ARGV[4]),integer(ARGV[5]),integer(ARGV[6])
if not expires or not window or window < 1 or window > horizon or not dimensions or (dimensions ~= 2 and dimensions ~= 4) or not aliases or aliases < 1 or aliases > 4 or not observed or observed > exact-horizon or #KEYS ~= 2+probes+dimensions*aliases or #ARGV ~= 6+dimensions*4 then return unavailable() end
local kinds = dimensions == 4 and {'tenant','canonical_network','device','canonical_identifier_digest'} or {'tenant','subject_or_network'}
local snapshots = {}
local reply = {'committed',fingerprint,text(observed)}
for i = 1, dimensions do
  local offset = 6+(i-1)*4
  local count,start,finish = integer(ARGV[offset+2]),integer(ARGV[offset+3]),integer(ARGV[offset+4])
  if ARGV[offset+1] ~= kinds[i] or not count or count < 1 or not start or not finish or start > observed or observed >= finish or finish-start ~= window then return unavailable() end
  snapshots[i] = {count=count,start=start,expires=finish}
  for j = 1,4 do reply[#reply+1] = ARGV[offset+j] end
end
local clock = redis.call('TIME')
local seconds,micros = integer(clock[1]),integer(clock[2])
if not seconds or not micros or micros > 999999 or seconds > math.floor((exact-horizon-999999)/1000000) then return unavailable() end
local now = seconds*1000000+micros
if now >= expires or expires > now+60000000 or observed > now then return unavailable() end
local types = {}
for i,key in ipairs(KEYS) do
  if #key > 256 then return unavailable() end
  types[i] = redis.call('TYPE',key).ok
  if types[i] ~= 'none' and types[i] ~= 'string' then return unavailable() end
end
if types[1] ~= 'string' or redis.call('STRLEN',KEYS[1]) > 128 or redis.call('GET',KEYS[1]) ~= marker then return unavailable() end
local function record(key,maximum,fields)
  if redis.call('STRLEN',key) > maximum then return nil end
  local value = redis.call('GET',key); if not value then return nil end
  return split(value,fields)
end
local replayValue = fingerprint .. '|committed|' .. table.concat(reply,'|')
local replayExpiry, free, replayPresent = observed+horizon,nil,false
if types[2] == 'string' then
  if redis.call('STRLEN',KEYS[2]) > 2508 then return unavailable() end
  local value = redis.call('GET',KEYS[2])
  if value ~= replayValue and value ~= fingerprint .. '|pending' then return unavailable() end
  replayPresent = value == replayValue
end
for i = 3,2+probes do
  if types[i] == 'none' then
    if not free then free = KEYS[i] end
  else
    local entry = record(KEYS[i],384,3)
    if not entry or #entry ~= 3 or #entry[1] > 256 or #entry[2] ~= 64 or not string.match(entry[2],'^[0-9a-f]+$') then return unavailable() end
    local at = integer(entry[3]); if not at or at > now+horizon then return unavailable() end
    if entry[1] == KEYS[2] then
      if entry[2] ~= fingerprint or at ~= replayExpiry then return unavailable() end
      free = KEYS[i]
    elseif at <= now and not free then free = KEYS[i] end
  end
end
if replayExpiry > now and not free then return unavailable() end
local changes = {}
for i,snapshot in ipairs(snapshots) do
  local offset = 2+probes+(i-1)*aliases
  local root,rootIndex,records = nil,nil,{}
  for j = 1,aliases do
    local index = offset+j
    if types[index] == 'string' then
      local fields = record(KEYS[index],384,4)
      if not fields or (#fields ~= 2 and #fields ~= 4) or #fields[1] > 256 or (#fields == 2 and fields[2] ~= 'alias') or (root and root ~= fields[1]) then return unavailable() end
      root,records[index] = fields[1],fields
    end
  end
  if root then
    for j = 1,aliases do if KEYS[offset+j] == root then rootIndex = offset+j end end
    if not rootIndex or not records[rootIndex] or #records[rootIndex] ~= 4 then return unavailable() end
    for index,fields in pairs(records) do if index ~= rootIndex and #fields ~= 2 then return unavailable() end end
  else rootIndex = offset+aliases; root = KEYS[rootIndex] end
  local start,count,priorStart = snapshot.start,snapshot.count,nil
  if records[rootIndex] then
    local fields = records[rootIndex]
    local priorCount,priorWindow = integer(fields[3]),integer(fields[4])
    priorStart = integer(fields[2])
    if not priorStart or not priorCount or priorCount < 1 or priorStart > now or priorStart > exact-window or priorWindow ~= window then return unavailable() end
    if priorStart > start then start,count = priorStart,priorCount
    elseif priorStart == start then count = math.max(count,priorCount) end
  end
  if start+window > now then
    local at = text(math.ceil((start+window)/1000))
    local value = root .. '|' .. text(start) .. '|' .. text(count) .. '|' .. text(window)
    if not records[rootIndex] or table.concat(records[rootIndex],'|') ~= value then changes[#changes+1] = {root,value,at} end
    for j = 1,aliases do
      local index = offset+j
      -- A prior partial restore may have moved the root before its aliases.
      -- Until the exact replay is acknowledged, repair their original expiry
      -- even when the root already contains this cumulative snapshot.
      if index ~= rootIndex and (not records[index] or priorStart ~= start or not replayPresent) then changes[#changes+1] = {KEYS[index],root .. '|alias',at} end
    end
  end
end
-- Marker stays replaying across partial errors. Restoring cumulative snapshots
-- with max/ordered windows is idempotent; a retry cannot add another attempt.
if replayExpiry > now then
  local at = text(math.ceil(replayExpiry/1000))
  local reservation = KEYS[2] .. '|' .. fingerprint .. '|' .. text(replayExpiry)
  if redis.call('GET',free) ~= reservation then redis.call('SET',free,reservation,'PXAT',at) end
  if not replayPresent and types[2] == 'none' then redis.call('SET',KEYS[2],fingerprint .. '|pending','PXAT',at) end
end
for _,change in ipairs(changes) do redis.call('SET',change[1],change[2],'PXAT',change[3]) end
if replayExpiry > now and not replayPresent then redis.call('SET',KEYS[2],replayValue,'PXAT',text(math.ceil(replayExpiry/1000))) end
return {'restored',fingerprint}
