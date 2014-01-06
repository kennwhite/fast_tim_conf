local args = ngx.get_uri_args
local key, status = memc_get(("exid_key_%d"):format(args['idx']))

nginx.say(crypt.encrypt(key, args['val']))
