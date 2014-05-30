local crypt = require('crypt')
local timfunc = require('timfun')

local testmode = true

ngx.req.read_body()
ngx.header['Access-Control-Allow-Origin'] =  '*';
ngx.header['Access-Control-Allow-Headers'] = 'IF-NONE-MATCH, X-ACR, FAIL';

local headers = ngx.req.get_headers()
local etag = headers['IF-NONE-MATCH']
local acr, tid, provider, exid, idx

if not etag and (headers['Cookie'] and headers['Cookie']:find("__acr")) then
  ngx.log(ngx.INFO, "ACR Cookie Present : ", headers['Cookie'])
  etag = string.match(headers['Cookie'], ".*__acr=([^;]+)")
end

if headers['MSISDN'] then -- TMO
  provider = 'TMO'
  acr = crypt.hash(headers['MSISDN']);
elseif headers['X-UIDH'] then -- VZN
  provider = 'VZW'
  acr = headers['X-UIDH']; 
elseif headers['x-up-subno'] then -- ATT
  provider = 'ATT'
  acr = headers['x-up-subno']
elseif testmode then
  if not etag and headers['FAIL'] == 'true' then
    ngx.exit(ngx.HTTP_NOT_FOUND)
  end
end

-- Fail if we don't have an etag or acr value
-- TODO move to fast_tim
if not acr and not etag then
  timfunc.build_empty_response()
  ngx.exit(ngx.HTTP_OK)
end

if acr then -- convert carrier trusted to tim trusted id
  tid = timfunc:get_mapped_ttid(acr)
else -- etag present, decode T-EID
  tid = timfunc:decode_etag(etag)
end

local teid = timfunc:build_teid(tid)

if testmode then
  timfunc:build_test_response(teid, tid)
else
  timfunc:build_response(teid)
end

