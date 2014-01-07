crypt = require('crypt')
local currentIdx = os.time()/60/60/24 - 15000

function encode_in_hex(str)
  return (str:gsub('.', function(s) return ('%X'):format(s:byte()) end))
end

function decode_hex(str)
  return (hex:gsub('..', function(v) return ("%c"):format(tonumber(v, 16)) end))
end

function build_response(exid)
  etag = string.format("\"%4d-%s\"", currentIdx, exid)
  ngx.header['ETag'] = etag
  --> set expires to something
  ngx.header['Expires'] = "Fri, 01 May 2020 03:47:24 GMT"
  ngx.header['Cache-Control'] = "max-age=315360000, private"
  ngx.header['Set-Cookie'] = string.format("__acr=%s;", etag)

  ngx.say(string.format("window.onload=function(){window.ACR={acr:'%s'}};window['exidInserted'] ? window.exidInserted('%s') : false;", exid, exid))
end

function format_new_acr(acr)
  return string.format("000-%s", acr)
end

function propigate_tid(acr, tid)
  -- TODO notify global, move to memcached proxy
  memc_set("acr_%s":format(acr), tid)
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

local headers = ngx.req.get_headers()
local acr = headers['X-ACR']
local etag = headers['IF-NONE-MATCH']
local tid

-- TODO move to fast_tim
if not acr and not etag then
  ngx.exit(ngx.HTTP_NOT_FOUND)
end

if acr then
  -- TODO acr decode if needed

  -- match up
  tid, status = memc_get(acr)
  if status == ngx.HTTP_NOT_FOUND then
    tid = crypt.hash(format_new_acr(acr))
    propigate_tid(acr, tid)
  end
else --> Roll forward
  local idx =  etag:match( "[^-]*" )
  local exid =  etag:match( "[^-]*-(.*)")

  local old_key, status = memc_get(("exid_key_%s"):format(idx))
  tid = crypt.decrypt(old_key, exid)
end

local key, status = memc_get(("exid_key_%d"):format(currentIdx)) --'password12344444444'
build_response(crypt.encrypt(key, tid))
