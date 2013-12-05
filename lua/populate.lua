crypt = require('crypt')

for i=1, 10000, 1 do
  ngx.location.capture("/cache",
    { method = ngx.HTTP_POST,
      body = string.format("%d",10000-i),
      args = { key = string.format("%d", i) }
    }
  )
end
