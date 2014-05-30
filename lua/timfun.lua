local crypt = require('crypt')
local memc = require('memc')

return {
  -- TODO should be static per execution
  currentIdx = function ()
    return math.floor(os.time()/60/60/24 - 15000)
  end,

  set_headers = function (self, exid)
    ngx.header['ETag'] = ("\"%4d-%s\""):format(self.currentIdx(), exid)
    --> set expires to something
    --ngx.header['Expires'] = "Fri, 01 May 2020 03:47:24 GMT"
    --ngx.header['Cache-Control'] = "max-age=315360000, private"
    ngx.header['Set-Cookie'] = ("__acr=%4d-%s; Expires=Wed, 09 Jun 2021 10:18:14 GMT; HttpOnly"):format(self.currentIdx(), exid) 
  end,
  
  build_empty_response = function ()
   ngx.say ( [[window.ACR=undefined;window['exidInserted'] ?
               window.exidInserted(undefined) : false; ]] )
  end,

  build_response = function (self, exid)
    self:set_headers(exid)
    local id = ("\"%4d-%s;ncc=9999;type=Dyna\""):format(self.currentIdx(), exid)
    ngx.say(([[window.ACR='%s';window['exidInserted'] ?
               window.exidInserted('%s') : false;]]):format(
                id,
                id))
  end,

  build_test_response = function (self, exid, trusted)
    self:set_headers(exid)
    local id = ("\"%4d-%s;ncc=9999;type=Dyna\""):format(self.currentIdx(), exid) 
    ngx.say(([[window['exidInserted'] ?
               window.exidInserted('%s', '%s') : false;]]):format(
                id,
                trusted)) 
  end,

  set_key_value = function (dict)
    ngx.location.capture(
      "/push",
      {
        method = ngx.HTTP_POST,
        args = dict
      }
    )
  end,

  get_decode_key = function (idx)
    local val = memc:get_with_fallback(("exid_key_%s"):format(idx),
                                       ("/keys/%s"):format(idx))

    if not val then
      ngx.log(ngx.ERR,
        "failed to retrieve decode/encode key from memcached or key value store")
      ngx.exit(500)
    end

    return val
  end,


  get_mapped_ttid = function (self, acr)
    local key = ("acr_%s"):format(acr)
    local val = memc:get_with_fallback(key, ("/acrs/%s"):format(acr))

    if not val then
      -- Generate a new new tim trusted id for this carrier trusted id
      val = crypt.hash(acr) -- TODO should use a global salt here
      memc:set(key, val)
      self.set_key_value({ acr = key, tim = val})
    end

    return val
  end,

  id_components = function(str)
    return str:match("(%d+)-([^;]+);ncc\=(%d+);type=(%a+)")
  end,

  decode_etag = function (self, etag)
    idx, exid = self.etag_components(etag)
    local old_key = self.get_decode_key(idx)
    return crypt.decrypt(old_key, exid)
  end,

  etag_components = function (str)
    return str:match("\"?(%d+)-(.*)\"?$")
  end,

  build_teid = function(self, tid)
    -- Get current key for encoding
    local currentIndex = self.currentIdx()
    local key = self.get_decode_key(currentIdx)
    return crypt.encrypt(key, tid)
  end
}
