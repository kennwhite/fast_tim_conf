crypt = require('crypt')
local currentIdx = os.time()/60/60/24 - 15000

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

function memc_delete(key)
  local resp = ngx.location.capture('/cache',
    { method = ngx.HTTP_DELETE,
      body = '',
      args = { key = key } 
    }
  )

  return resp.body, resp.status
end

function memc_update(key, val)
  local resp = ngx.location.capture('/cache',
    { method = ngx.HTTP_PUT,
      body = val,
      args = { key = key } 
    }
  )

  return resp.body, resp.status
end


local args = ngx.req.get_uri_args() 

local new_tid = crypt.hash(("%d%s"):format(math.random(100000), args.acr))

res, status = memc_update(("acr_%s"):format(args.acr), new_tid)
res2, status2 = memc_set(("tid_%s"):format(new_tid), args.acr)

ngx.say(args.acr)
ngx.say(new_tid)

ngx.say(res, status)
ngx.say(res2, status2)
