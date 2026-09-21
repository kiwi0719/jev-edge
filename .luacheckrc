std = "luajit"
max_line_length = 120

files["core/"] = {
  -- core must never touch ngx
  globals = {},
}

files["adapters/openresty/"] = {
  globals = { "ngx", "ndk" },
}

files["bench/"] = {
  globals = { "ngx" },
  max_line_length = 200,   -- report strings
}

files["bench/wrk-post.lua"] = {
  globals = { "wrk", "request", "done" },
  unused_args = false,
}

exclude_files = { "t/servroot/", "lua_modules/" }

files["adapters/openresty/spec/"] = {
  std = "+busted",
}

files["core/spec/"] = {
  std = "+busted",
}
