-- resty/jev/providers/laya.lua
-- A fine-tuned Laya model behind adapters/laya-server (or any other server
-- that passes conformance/). Same System One request as providers/jev.lua; a
-- provider of its own so the cache, the log and `make calibrate` keep its
-- scores apart from jev's: the two are not on the same scale.
-- Start from adapters/laya-server/jev-laya.conf.lua, not from the jev defaults.

return require("resty.jev.providers.jev").system_one("laya", {
  model = "laya",
  url   = "http://127.0.0.1:8080/v1/systemone",
})
