package sessionvalkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"
)

// INFO is deliberately inside the same script as marker/entry observation. A
// restored snapshot or promoted server cannot reuse a previous process's epoch.
// The selected standalone primary must permit INFO server/cluster/replication,
// EVAL, TIME, HGET/HSET/HLEN, DEL and PEXPIRE. ACL denial is a miss, not authentication.
// No script scans keys or grows an index beyond MaximumScopes + three fields.
const cacheScript = `
local server = redis.call('INFO', 'server')
local boot = string.match(server, '\r\nrun_id:([0-9a-f]+)\r\n')
local cluster = redis.call('INFO', 'cluster')
local replication = redis.call('INFO', 'replication')
if not boot or string.len(boot) ~= 40 or not string.find(cluster, 'cluster_enabled:0\r\n', 1, true) or not string.find(replication, 'role:master\r\n', 1, true) then return redis.error_reply('unsupported topology') end
local mode = ARGV[1]
if mode == 'probe' then return {'','',''} end
local marker = KEYS[1]
local epoch = redis.call('HGET', marker, 'epoch')
local barrier = redis.call('HGET', marker, 'barrier')
if redis.call('HGET', marker, 'boot') ~= boot or not epoch or string.len(epoch) ~= 64 or not barrier or string.len(barrier) ~= 64 or redis.call('HLEN', marker) > tonumber(ARGV[3]) + 3 then
 redis.call('DEL', marker)
 epoch = ARGV[2]
 barrier = ARGV[2]
 redis.call('HSET', marker, 'boot', boot, 'epoch', epoch, 'barrier', barrier)
end
redis.call('PEXPIRE', marker, 20000)
if mode == 'read' then
 for i = 2, #KEYS do
  local entry = KEYS[i]
  if redis.call('HGET', entry, 'epoch') == epoch then
   local s = redis.call('HGET', entry, 's')
   local f = redis.call('HGET', entry, 'f')
   if s and f and string.len(s) == 66 and string.len(f) == 66 and (redis.call('HGET', marker, s) or '') == (redis.call('HGET', entry, 'sg') or '') and (redis.call('HGET', marker, f) or '') == (redis.call('HGET', entry, 'fg') or '') then
    local blob = redis.call('HGET', entry, 'blob')
    if blob and string.len(blob) <= tonumber(ARGV[4]) then return {epoch, barrier, blob} end
   end
  end
 end
 return {epoch, barrier, ''}
end
if mode == 'fill' then
 if epoch ~= ARGV[5] or barrier ~= ARGV[6] then return {'','',''} end
 local serverTime = redis.call('TIME')
 local serverMillis = tonumber(serverTime[1]) * 1000 + math.floor(tonumber(serverTime[2]) / 1000)
 local ttl = math.min(tonumber(ARGV[10]), tonumber(ARGV[11]) - serverMillis)
 if ttl < 1 then return {'','',''} end
 redis.call('DEL', KEYS[2])
 redis.call('HSET', KEYS[2], 'epoch', epoch, 's', ARGV[7], 'f', ARGV[8], 'sg', redis.call('HGET', marker, ARGV[7]) or '', 'fg', redis.call('HGET', marker, ARGV[8]) or '', 'blob', ARGV[9])
 redis.call('PEXPIRE', KEYS[2], ttl)
 return {epoch, barrier, ''}
end
if mode == 'invalidate' then
 local field = ARGV[5]
 if not redis.call('HGET', marker, field) and redis.call('HLEN', marker) >= tonumber(ARGV[3]) + 3 then
  redis.call('DEL', marker)
  epoch = ARGV[2]
  redis.call('HSET', marker, 'boot', boot, 'epoch', epoch)
 end
 redis.call('HSET', marker, 'barrier', ARGV[2], field, ARGV[2])
 redis.call('PEXPIRE', marker, 20000)
 return {epoch, ARGV[2], ''}
end
return redis.error_reply('invalid operation')
`

func (c *Cache) run(ctx context.Context, mode, marker string, entries, args []string) ([]string, error) {
	bounded, cancel := context.WithTimeout(ctx, c.config.CacheTimeout)
	defer cancel()
	client, err := c.client(bounded)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	keys := []string{}
	if marker != "" {
		keys = append(keys, marker)
	}
	keys = append(keys, entries...)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	arguments := []string{mode, hex.EncodeToString(nonce), strconv.Itoa(c.config.MaximumScopes), strconv.Itoa(c.config.MaximumPayloadBytes)}
	arguments = append(arguments, args...)
	command := client.B().Eval().Script(cacheScript).Numkeys(int64(len(keys))).Key(keys...).Arg(arguments...).Build()
	values, err := client.Do(bounded, command).AsStrSlice()
	if err != nil {
		return nil, unavailable("command", err)
	}
	if bounded.Err() != nil {
		return nil, unavailable("command-context", bounded.Err())
	}
	if len(values) != 3 {
		return nil, unavailable("response-length", nil)
	}
	if mode != "probe" && values[0] != "" && (len(values[0]) != 64 || len(values[1]) != 64) {
		return nil, unavailable("response-metadata", nil)
	}
	if len(values[2]) > c.config.MaximumPayloadBytes {
		return nil, unavailable("response-payload", nil)
	}
	return values, nil
}

func milliseconds(remaining time.Duration) (string, bool) {
	if remaining < time.Millisecond || remaining > 20*time.Second {
		return "", false
	}
	return strconv.FormatInt(remaining.Milliseconds(), 10), true
}
