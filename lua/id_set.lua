crypt = require('crypt')

local currentIdx = math.floor(os.time()/60/60/24 - 15000)
local testmode = true

function set_headers(exid)
  local full_id = ("\"%4d-%s;ncc=9999;type=Dyna\""):format(currentIdx, exid)
  ngx.header['ETag'] = ("\"%4d-%s\""):format(currentIdx, exid)

  --> set expires to something
  ngx.header['Expires'] = "Fri, 01 May 2020 03:47:24 GMT"
  ngx.header['Cache-Control'] = "max-age=315360000, private"
  ngx.header['Set-Cookie'] = string.format("__acr=%4d-%s; path=/", currentIdx, exid) 
end

function build_response(exid)
  set_headers(exid)
  local full_id = ("\"%4d-%s;ncc=9999;type=Dyna\""):format(currentIdx, exid) 
  ngx.say(string.format("window.ACR='%s';window['exidInserted'] ? window.exidInserted('%s') : false;", full_id, full_id)) 
end

function build_test_response(exid, trusted)
  set_headers(exid)
  local full_id = ("\"%4d-%s;ncc=9999;type=Dyna\""):format(currentIdx, exid) 
  ngx.say(string.format("window['exidInserted'] ? window.exidInserted('%s', '%s') : false;", full_id, trusted)) 

end

-- TODO we may want to buffer these requests
function push_data(premature, acr, tid)
  ngx.location.capture(
    "/push",
    {
      method = ngx.HTTP_POST,
      args = { acr = acr, tim = tid }
    }
  )
end

-- TODO Memcached Proxy should notify TIM backend server of new id
function propigate_tid(acr, tid)
  memc_set(("acr_%s"):format(acr), tid)

  -- TODO Use timer
  -- TODO By Default max pending timers of 1024 - we need a failure case
  --local ok, err = ngx.timer.at(0, push_data, acr, tid)
  ngx.location.capture(
    "/push",
    {
      method = ngx.HTTP_POST,
      args = { acr = acr, tim = tid }
    }
  )

  if not ok then
    ngx.log(ngx.ERR, "failed to create push_data timer: ", err)
  end
end

function memc_set(key, val)
  local resp = ngx.location.capture('/cache',
    { method = ngx.HTTP_POST,
      body = val,
      args = { key = key:lower() } 
    }
  )

  return resp.body, resp.status
end

function memc_get(key)
  local resp = ngx.location.capture('/cache',
    { method = ngx.HTTP_GET,
      body = '',
      args = { key = key:lower() } 
    }
  )

  return resp.body, resp.status
end

function decode_id(str)
  return str:match("(%d+)-([%d%a]+);ncc\=(%d+);type=(%a+)")
end

function decode_etag(str)
  return str:match("\"?(%d+)-(.*)\"?$")
end

ngx.header['Access-Control-Allow-Origin'] =  '*';
ngx.header['Access-Control-Allow-Headers'] = 'IF-NONE-MATCH, X-ACR, FAIL';

local headers = ngx.req.get_headers()
local acr = headers['X-ACR']
local etag = headers['IF-NONE-MATCH']
local tid

if headers['MSISDN'] then
  acr = string.format("1000-%s;ncc=111;type=Dyno", headers['MSISDN']); 
elseif testmode then
  if headers['Referer'] and (string.find(headers['Referer'], '9292') or string.find(headers['Referer'], 'wan') or string.find(headers['Referer'], 'www.timdemo.net')) then  
    if headers['Cookie'] then
      acr = string.format("%s;ncc=111;type=Dyno", string.match(headers['Cookie'], ".*_fake_acr=([^;]+)")); 
    end
  end

  if not etag and headers['FAIL'] == 'true' then
    ngx.exit(ngx.HTTP_NOT_FOUND)
  end
end

-- Fail if we don't have an etag or acr value
-- TODO move to fast_tim
if not acr and not etag then
  ngx.exit(ngx.HTTP_OK)
end

if acr then
  -- Decode carrier external to carrier trusted - assumes if key not found
  -- that passed in key is the trusted 
  local c_key_index, c_id, c_op = decode_id(acr)
  carrier_key, status = memc_get(("carrier_%d_key_%d"):format(c_op, c_key_index))

  if status == ngx.HTTP_FOUND then
    c_id = crypt.decrypt(carrier_key, c_id)
  end

  -- convert carrier trusted to tim trusted id
  tid, status = memc_get(("acr_%s"):format(acr))

  -- Generate a new new tim trusted id for this carrier trusted id
  if status == ngx.HTTP_NOT_FOUND then
    tid = crypt.hash(acr)
    propigate_tid(acr, tid)
  end

else -- etag present - roll forward
  idx, exid = decode_etag(etag)
  local old_key, status = memc_get(("exid_key_%s"):format(idx))
  tid = crypt.decrypt(old_key, exid)
end

-- Get current key for encoding
local key, status = memc_get(("exid_key_%d"):format(currentIdx))

if testmode then
  build_test_response(crypt.encrypt(key, tid), tid)
else
  build_response(crypt.encrypt(key, tid))
end

