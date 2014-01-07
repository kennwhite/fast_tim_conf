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
local val, status = memc_get(("acr_%s"):format(args.acr)) 
ngx.say(val) 
