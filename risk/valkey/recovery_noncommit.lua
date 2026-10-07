-- Prove absence of conflicting native attempt state under the exact live fence.
-- Read-only: never debit, clear unresolved state or refresh retention.
local function unavailable() return {'unavailable',''} end
local function integer(v)
  if type(v)~='string' or #v<1 or #v>16 or not string.match(v,'^%d+$') or (#v>1 and string.sub(v,1,1)=='0') then return nil end
  local n=tonumber(v); if not n or n>9007199254740991 then return nil end; return n
end
local function split(v,maximum)
  local fields={}
  for field in string.gmatch(v..'|','(.-)|') do
    if #fields>=maximum then return nil end
    fields[#fields+1]=field
  end
  return fields
end
if #KEYS~=10 or #ARGV~=2 or #ARGV[1]>128 or #ARGV[2]~=64 or not string.match(ARGV[2],'^[0-9a-f]+$') then return unavailable() end
local fence=split(ARGV[1],5)
if not fence or #fence~=5 or fence[1]~='replaying' then return unavailable() end
for _,i in ipairs({2,4}) do
  if #fence[i]~=32 or not string.match(fence[i],'^[0-9a-f]+$') or fence[i]==string.rep('0',32) then return unavailable() end
end
if #fence[3]<1 or #fence[3]>20 or not string.match(fence[3],'^[1-9]%d*$') or (#fence[3]==20 and fence[3]>'18446744073709551615') then return unavailable() end
local expires=integer(fence[5])
local clock=redis.call('TIME')
local seconds,micros=integer(clock[1]),integer(clock[2])
if not expires or not seconds or not micros or micros>999999 or seconds>math.floor((9007199254740991-60000000-999999)/1000000) then return unavailable() end
local now=seconds*1000000+micros
if now>=expires or expires>now+60000000 then return unavailable() end
for i,key in ipairs(KEYS) do
  if #key<1 or #key>256 then return unavailable() end
  local kind=redis.call('TYPE',key).ok
  if kind~='none' and kind~='string' then return unavailable() end
  if i==1 then
    if kind~='string' or redis.call('STRLEN',key)>128 or redis.call('GET',key)~=ARGV[1] then return unavailable() end
  elseif i==2 then
    -- Any retained root is conflicting, including pending, corrupt or committed.
    if kind~='none' then return unavailable() end
  elseif kind=='string' then
    if redis.call('STRLEN',key)>384 then return unavailable() end
    local fields=split(redis.call('GET',key),3)
    if not fields or #fields~=3 or #fields[1]<1 or #fields[1]>256 or #fields[2]~=64 or not string.match(fields[2],'^[0-9a-f]+$') or not integer(fields[3]) then return unavailable() end
    -- A lost root with its original directory entry is not absence evidence.
    if fields[1]==KEYS[2] then return unavailable() end
  end
end
return {'not_committed',ARGV[2]}
