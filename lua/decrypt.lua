crypt = require('crypt') 

function memc_get(key) 
  local resp = ngx.location.capture('/cache', 
    { method = ngx.HTTP_GET, 
      body = '', 
      args = { key = key }  
    } 
  ) 
 
  return resp.body, resp.status 
end 

local args = ngx.req.get_uri_args() 
local key, status = memc_get(("exid_key_%d"):format(args.idx)) 
ngx.say(crypt.decrypt(key, args.val)) 
