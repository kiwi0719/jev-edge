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
}

exclude_files = { "t/servroot/", "lua_modules/" }

files["core/spec/"] = {
  std = "+busted",
}
