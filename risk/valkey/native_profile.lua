-- Read-only server facts; not primary health or whole-counter continuity.
if #KEYS ~= 0 or #ARGV ~= 0 then return {'unavailable',''} end
local info = redis.call('INFO','server','memory','replication','stats')
if type(info) ~= 'string' or #info > 16384 then return {'unavailable',''} end
local wanted = {run_id=true,maxmemory_policy=true,role=true,connected_slaves=true,evicted_keys=true}
local fields = {}
for line in string.gmatch(info,'[^\r\n]+') do
  local key,value = string.match(line,'^([%w_]+):([^\r\n]+)$')
  if key and wanted[key] then
    if fields[key] then return {'unavailable',''} end
    fields[key] = value
  end
end
local boot,evictions = fields.run_id,fields.evicted_keys
if not boot or #boot ~= 40 or not string.match(boot,'^[0-9a-f]+$') or boot == string.rep('0',40) or fields.maxmemory_policy ~= 'noeviction' or fields.role ~= 'master' or fields.connected_slaves ~= '0' then return {'unavailable',''} end
if not evictions or #evictions > 20 or not string.match(evictions,'^%d+$') or (#evictions > 1 and string.sub(evictions,1,1) == '0') or (#evictions == 20 and evictions > '18446744073709551615') then return {'unavailable',''} end
return {boot,evictions}
