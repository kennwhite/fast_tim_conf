crypt = require('crypt')

local currentIdx = math.floor(os.time()/60/60/24 - 15000)
local testmode = true

function set_headers(exid)
  local full_id = ("\"%4d-%s;ncc=9999;type=Dyna\""):format(currentIdx, exid)
  ngx.header['ETag'] = ("\"%4d-%s\""):format(currentIdx, exid)

  --> set expires to something
  --ngx.header['Expires'] = "Fri, 01 May 2020 03:47:24 GMT"
  --ngx.header['Cache-Control'] = "max-age=315360000, private"
  ngx.header['Set-Cookie'] = string.format("__acr=%4d-%s; Expires=Wed, 09 Jun 2021 10:18:14 GMT; HttpOnly", currentIdx, exid) 
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

-- TODO Use timer
-- By Default max pending timers of 1024 - we need a failure case
--local ok, err = ngx.timer.at(0, push_data, acr, tid)
-- we may want to buffer these requests
--function push_data(premature, acr, tid)
--  ngx.location.capture(
--  "/push",
--  {
--    method = ngx.HTTP_POST,
--    args = { acr = acr, tim = tid }
--  }
--  )
--end
--if not ok then
--  ngx.log(ngx.ERR, "failed to create push_data timer: ", err)
--end

function set_key_value(dict)
  ngx.location.capture(
    "/push",
    {
      method = ngx.HTTP_POST,
      args = dict
    }
  )
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

function memc_get_with_fallback(key, fallback)
  local val, status = memc_get(key)

  if status != ngx.HTTP_FOUND then
    -- if not found in memcached check key value store
    res = ngx.location.capture(
      fallback,
      {
        method = ngx.HTTP_GET
      }
    )

    if res.status == ngx.HTTP_FOUND then
      val = res.body

      -- set in local lookup so we dont need to go back to key value store
      memc_set(key, val)
    else
      val = nil
    end
  end

  return val
end

function get_decode_key(idx)
  val = memc_get_with_fallback(("exid_key_%s"):format(idx), ("/keys/%s"):format(idx))

  if !val then
    ngx.log(ngx.ERR, "failed to retrieve decode/encode key from memcached or key value store")
    ngx.exit(500)
  end

  return val
end

function get_mapped_ttid(acr)
  local key = ("acr_%s"):format(acr)
  val = memc_get_with_fallback(key, ("/acrs/%s"):format(acr))

  if !val then
    -- Generate a new new tim trusted id for this carrier trusted id
    val = crypt.hash(acr)
    memc_set(key, tid)
    set_key_value({ id = acr, tim = tid })
  end

  return val
end

function decode_id(str)
  return str:match("(%d+)-([^;]+);ncc\=(%d+);type=(%a+)")
end

function decode_etag(str)
  return str:match("\"?(%d+)-(.*)\"?$")
end

ngx.req.read_body
ngx.header['Access-Control-Allow-Origin'] =  '*';
ngx.header['Access-Control-Allow-Headers'] = 'IF-NONE-MATCH, X-ACR, FAIL';

local headers = ngx.req.get_headers()
local acr = headers['X-ACR']
local etag = headers['IF-NONE-MATCH']
local tid
if not etag and (headers['Cookie'] and headers['Cookie']:find("__acr")) then
  ngx.log(ngx.ERR, "COOKIE HERE", headers['Cookie'])
  etag = string.match(headers['Cookie'], ".*__acr=([^;]+)")
end

if headers['MSISDN'] then -- TMO
  msdn = crypt.hash(headers['MSISDN']);
  acr = string.format("1000-%s;ncc=222;type=Dyno", msdn); 
elseif headers['X-UIDH'] then -- VZN
  acr = string.format("1000-%s;ncc=333;type=Dyno", headers['X-UIDH']); 
-- TODO change to x-up-subno
elseif headers['x-att-deviceid'] then -- ATT
  acr = string.format("1000-%s;ncc=444;type=Dyno", headers['x-att-deviceid']); 
elseif testmode then
  if headers['Referer'] and (string.find(headers['Referer'], '9292') or string.find(headers['Referer'], 'wan') or string.find(headers['Referer'], 'www.timdemo.net')) then  
    if headers['Cookie'] then
      acr = string.format("%s;ncc=111;type=Dyno", string.match(headers['Cookie'], ".*_fake_acr=([^;]+)"))
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
  -- convert carrier trusted to tim trusted id
  tid = get_mapped_ttid(acr)
else -- etag present - roll forward
  
  idx, exid = decode_etag(etag)
  local old_key = get_decode_key(idx)
  tid = crypt.decrypt(old_key, exid)
end

-- Get current key for encoding
local key = get_decode_key(currentIdx)

if testmode then
  build_test_response(crypt.encrypt(key, tid), tid)
else
  build_response(crypt.encrypt(key, tid))
end

