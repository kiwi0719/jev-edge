use Test::Nginx::Socket::Lua;
require "./t/lib.pl";

plan 'no_plan';
master_on();
workers(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: Traefik style with forwardBody: full L2 verdict
--- http_config eval: $::HttpConfig
--- user_files eval: ::conf()
--- config
location = /_jev/forward-auth { content_by_lua_block { require("resty.jev.edge").forward_auth() } }
--- request
POST /_jev/forward-auth
{"messages":[{"role":"user","content":"Please summarise the attached quarterly report for me."}]}
--- more_headers
Content-Type: application/json
X-Forwarded-Method: POST
X-Forwarded-Uri: /v1/chat/completions?stream=false
X-Forwarded-For: 198.51.100.9
X-Jev-Mock-Score: 0.2
--- error_code: 200
--- response_headers
X-Jev-Verdict: safe
X-Jev-Source: l2
--- no_error_log
[error]



=== TEST 2: Caddy / nginx style without body: skipped with reason "no body"
--- http_config eval: $::HttpConfig
--- user_files eval: ::conf()
--- config
location = /_jev/forward-auth { content_by_lua_block { require("resty.jev.edge").forward_auth() } }
--- request
GET /_jev/forward-auth
--- more_headers
Content-Type: application/json
X-Forwarded-Method: POST
X-Forwarded-Uri: /v1/chat/completions
--- error_code: 200
--- response_headers
X-Jev-Verdict: skipped
X-Jev-Source: l1
X-Jev-Reason: no+body



=== TEST 3: headers-only request from a blocked IP is still denied
--- http_config eval: $::HttpConfig
--- user_files eval: ::conf('policy = { mode = "enforce", block_threshold = 0.7, suspect_threshold = 0.5 },')
--- config
location = /_jev/forward-auth { content_by_lua_block { require("resty.jev.edge").forward_auth() } }
location = /poison {
    content_by_lua_block {
        require("resty.jev.cache").new("jev_cache"):set("rep:203.0.113.77", { blocked_until = ngx.now() + 60 })
        ngx.say("ok")
    }
}
--- request eval
["GET /poison", "GET /_jev/forward-auth"]
--- more_headers
X-Original-Method: POST
X-Original-URI: /v1/chat/completions
X-Forwarded-For: 203.0.113.77
--- error_code eval
[200, 403]
--- response_body_like eval
["ok", "request rejected"]



=== TEST 4: real nginx auth_request wiring: verdict headers reach the upstream
--- http_config eval
qq{
$::HttpConfig
server {
    listen 1985;
    location / { $::Echo }
}
}
--- user_files eval: ::conf()
--- config
location = /_jev/forward-auth {
    internal;
    content_by_lua_block { require("resty.jev.edge").forward_auth() }
}
location /v1/ {
    auth_request /_jev/forward-auth;
    auth_request_set $jev_verdict $sent_http_x_jev_verdict;
    auth_request_set $jev_score   $sent_http_x_jev_score;
    auth_request_set $jev_source  $sent_http_x_jev_source;
    proxy_set_header X-Jev-Verdict $jev_verdict;
    proxy_set_header X-Jev-Score   $jev_score;
    proxy_set_header X-Jev-Source  $jev_source;
    proxy_pass http://127.0.0.1:1985;
}
--- request
POST /v1/chat/completions
{"messages":[{"role":"user","content":"Please summarise the attached quarterly report for me."}]}
--- more_headers
Content-Type: application/json
--- response_body
verdict=skipped score=0.00 source=l1 reason=-
--- no_error_log
[error]



=== TEST 5: a percent-encoded original URI is decoded before the watch list
--- http_config eval: $::HttpConfig
--- user_files eval: ::conf()
--- config
location = /_jev/forward-auth { content_by_lua_block { require("resty.jev.edge").forward_auth() } }
--- request
POST /_jev/forward-auth
{"messages":[{"role":"user","content":"Please summarise the attached quarterly report for me."}]}
--- more_headers
Content-Type: application/json
X-Forwarded-Method: POST
X-Forwarded-Uri: //v1/%63hat/completions
X-Forwarded-For: 198.51.100.9
X-Jev-Mock-Score: 0.2
--- error_code: 200
--- response_headers
X-Jev-Verdict: safe
X-Jev-Source: l2
--- no_error_log
[error]
