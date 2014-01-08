crypt = require('crypt')
local currentIdx = os.time()/60/60/24 - 15000

function encode_in_hex(str)
  return (str:gsub('.', function(s) return ('%X'):format(s:byte()) end))
end

function decode_hex(str)
  return (hex:gsub('..', function(v) return ("%c"):format(tonumber(v, 16)) end))
end

function build_response(exid)
  local full_id = "\"%4d-%s;ncc=9999;type=Dyna\"":format(currentIdx, exid)
  ngx.header['ETag'] = full_id
  --> set expires to something
  ngx.header['Expires'] = "Fri, 01 May 2020 03:47:24 GMT"
  ngx.header['Cache-Control'] = "max-age=315360000, private"
  ngx.header['Set-Cookie'] = string.format("__acr=%s;", full_id)

  ngx.say(string.format("window.onload=function(){window.ACR={acr:'%s'}};window['exidInserted'] ? window.exidInserted('%s') : false;", full_id, full_id))
end

-- TODO is this necessary?
--function format_new_trusted_id(acr)
--  return string.format("000-%s", acr)
--end

function propigate_tid(acr, tid)
  -- TODO notify global, move to memcached proxy
  memc_set(("acr_%s"):format(acr), tid)
end

function memc_set(key, val)
  local resp = ngx.location.capture('/cache',
    { method = ngx.HTTP_POST,
      body = val,
      args = { key = key } 
    }
  )

  return resp.body, resp.status
end

function memc_get(key)
  local resp = ngx.location.capture('/cache',
    { method = ngx.HTTP_GET,
      body = '',
      args = { key = key } 
    }
  )

  return resp.body, resp.status
end

function decode_id(str)
  return str:match("(%d+)-([%d%a]+);ncc\=(%d+);type=(%a+)")
end

local headers = ngx.req.get_headers()
local acr = headers['X-ACR']
local etag = headers['IF-NONE-MATCH']
local tid

-- Fail if we don't have an etag or acr value
-- TODO move to fast_tim
if not acr and not etag then
  ngx.exit(ngx.HTTP_NOT_FOUND)
end

if acr then
  -- Decode carrier external to carrier trusted - assumes if key not found
  -- that passed in key is the trusted 
  local c_key_index, c_id, c_op = decode_id(acr)
  carrier_key, status = memc_get("carrier_%d_key_%d":format(c_op, c_c_key_index))

  if status == ngx.HTTP_FOUND then
    c_id = crypt.decrypt(carrier_key, c_id)
  end

  -- convert carrier trusted to tim trusted id
  tid, status = memc_get("acr_%s":format(c_id))

  -- Generate a new new tim trusted id for this carrier trusted id
  if status == ngx.HTTP_NOT_FOUND then
    tid = crypt.hash(acr)
    propigate_tid(acr, tid)
  end

else -- etag present - roll forward
  idx, exid = decode_id(str)

  local old_key, status = memc_get(("exid_key_%s"):format(idx))
  tid = crypt.decrypt(old_key, exid)

end

local key, status = memc_get(("exid_key_%d"):format(currentIdx)) --'password12344444444'
build_response(crypt.encrypt(key, tid))
