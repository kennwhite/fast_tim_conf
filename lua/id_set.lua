ngx.req.discard_body()
local currentIdx = os.time()/60/60/24 - 15000
local headers = ngx.req.get_headers()

function build_response(index, exid)
  encoded = string.format("\"%4d-%x\"", index, exid)
  ngx.header['ETag'] = encoded
  ngx.header['Expires'] = "Fri, 01 May 2020 03:47:24 GMT"
  ngx.header['Cache-Control'] = "max-age=315360000, private"
  ngx.header['Set-Cookie'] = string.format("__acr=%s;", encoded)

  ngx.say(string.format("window.onload=function(){window.ACR={acr:'%d'}};window['exidInserted'] ? window.exidInserted('%d') : false;", exid, exid))
end

if not headers['X-ACR'] then
  ngx.exit(ngx.HTTP_NOT_FOUND)
else
  res = ngx.location.capture('/cache', {method = ngx.HTTP_GET, body = '', args = {key = string.format("%d", math.random(10000))}})

  --> etag format xxxxIIIIIIIII
  build_response(currentIdx, tonumber(res.body))
end

