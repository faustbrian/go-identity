-- Shared bounded marker profile; parsing is not primary confirmation.
local function publicationDecimal(v, maximum)
  if type(v) ~= 'string' or #v < 1 or #v > #maximum or not string.match(v, '^%d+$') or (#v > 1 and string.sub(v, 1, 1) == '0') then return false end
  return #v < #maximum or v <= maximum
end
local function publicationInteger(v)
  if not publicationDecimal(v, '9007199254740991') then return nil end
  return tonumber(v)
end
local function publicationFields(value, state, epoch)
  if type(value) ~= 'string' or #value > 384 then return nil end
  local fields = {}
  for field in string.gmatch(value .. '|', '(.-)|') do
    if #fields == 11 then return nil end
    fields[#fields+1] = field
  end
  if #fields ~= 11 or fields[1] ~= state or (epoch and fields[2] ~= epoch) then return nil end
  for _, i in ipairs({2,4,6}) do
    local size = i == 6 and 64 or 32
    if #fields[i] ~= size or not string.match(fields[i], '^[0-9a-f]+$') or fields[i] == string.rep('0',size) then return nil end
  end
  if not publicationDecimal(fields[3], '18446744073709551615') or fields[3] == '0' or not publicationDecimal(fields[7], '9223372036854775807') or fields[11] ~= '3600000000' then return nil end
  local expiry, from, through, started = publicationInteger(fields[5]), publicationInteger(fields[8]), publicationInteger(fields[9]), publicationInteger(fields[10])
  if not expiry or not from or not through or not started or from <= 0 or started <= 0 or through >= expiry or from > through-3600000000 or started > through-3600000000 then return nil end
  return fields
end
