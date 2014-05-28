return {
  set = function(self, key, val)
    local resp = ngx.location.capture('/cache',
      { method = ngx.HTTP_POST,
        body = val,
        args = { key = key:lower() } 
      }
    )

    return resp.body, resp.status
  end,

  get = function(self, key)
    local resp = ngx.location.capture('/cache',
      { method = ngx.HTTP_GET,
      body = '',
      args = { key = key:lower() } 
      }
    )

    return resp.body, resp.status
  end,

  get_with_fallback = function(self, key, fallback)
    local v, st = self:get(key)

    if st == 200 then
      return v
    end

    -- if not found in memcached check key value store
    res = ngx.location.capture(
      fallback,
      {
        method = ngx.HTTP_GET
      }
    )
      
    if (res.status == 200) then
      v = res.body

      -- set in local lookup so we dont need to go back to key value store
      self:set(key, v)

      return v
    else
      return nil
    end
  end
}
