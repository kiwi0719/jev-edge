use Test::Nginx::Socket::Lua;
require "./t/lib.pl";

# Which judge errors count against the breaker, through the real HTTP client
# (resty/jev/http.lua) and the openai-compat provider. Only a transport error,
# a timeout, a 5xx or a 429 is a breaker failure. A 200 the judged text made
# unusable (a refusal, keys other than the questions) and a 4xx it provoked (a
# provider's content filter) fail open all the same, but count nothing: the
# client cannot switch L2 off for every tenant with them.
#
# The stub judge on :1986 answers by what the judged text contains: SCORE ->
# injection 0.3, DOWN -> 503, FILTER -> Azure's 400 content_filter, anything
# else -> a refusal (content null).
our $Judge = q{
server {
    listen 1986;
    location / {
        content_by_lua_block {
            local cjson = require "cjson.safe"
            ngx.req.read_body()
            local req = cjson.decode(ngx.req.get_body_data() or "") or {}
            local user = req.messages and req.messages[2] and req.messages[2].content or ""
            ngx.header["Content-Type"] = "application/json"
            if user:find("SCORE", 1, true) then
                ngx.say(cjson.encode({ choices = { { message = { role = "assistant", content = '{"injection": 0.3}' } } } }))
            elseif user:find("DOWN", 1, true) then
                ngx.status = 503
                ngx.say('{"error":"down"}')
            elseif user:find("FILTER", 1, true) then
                ngx.status = 400
                ngx.say('{"error":{"code":"content_filter","status":400}}')
            else
                ngx.say('{"choices":[{"message":{"role":"assistant","content":null,"refusal":"I cannot help with that."}}]}')
            end
        }
    }
}
};

# min_samples 2, fail_ratio 0.5: two counted failures open the breaker
sub bconf {
    my ($open_s) = @_;
    $open_s //= 30;
    return ::conf(qq{
  jev = { provider = "openai-compat", endpoint = "http://127.0.0.1:1986/v1", api_key = "k", timeout_ms = 1000, timeout_max_ms = 1000 },
  policy = { mode = "enforce", block_threshold = 0.85, suspect_threshold = 0.5 },
  async = { enabled = false },
  breaker = { window_s = 60, min_samples = 2, fail_ratio = 0.5, open_s = $open_s },
});
}

sub chat {
    my ($text) = @_;
    return "POST /v1/chat/completions\n{\"messages\":[{\"role\":\"user\",\"content\":\"$text\"}]}";
}

plan 'no_plan';
master_on();
workers(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a judge that answers 200 with nothing usable 25 times never opens the breaker
--- http_config eval: "$::HttpConfig $::Judge"
--- user_files eval: ::bconf()
--- config eval: "location /v1/chat/completions { $::Access $::Echo }"
--- request eval
[(map { ::chat("please summarise the quarterly figures, request number $_") } 1..25),
 ::chat("SCORE please summarise the quarterly figures once more")]
--- more_headers
Content-Type: application/json
--- response_body eval
[(map { "verdict=error score=0.00 source=l2 reason=unusable%3A+openai-compat%3A+no+content\n" } 1..25),
 "verdict=safe score=0.30 source=l2 reason=injection+0.30\n"]
--- no_error_log
[error]



=== TEST 2: the judge's own content-filter 400, 25 times, never opens the breaker
--- http_config eval: "$::HttpConfig $::Judge"
--- user_files eval: ::bconf()
--- config eval: "location /v1/chat/completions { $::Access $::Echo }"
--- request eval
[(map { ::chat("FILTER please summarise the quarterly figures, request number $_") } 1..25),
 ::chat("SCORE please summarise the quarterly figures once more")]
--- more_headers
Content-Type: application/json
--- response_body eval
[(map { "verdict=error score=0.00 source=l2 reason=rejected%3A+openai-compat+http+400\n" } 1..25),
 "verdict=safe score=0.30 source=l2 reason=injection+0.30\n"]
--- no_error_log
[error]



=== TEST 3: a judge answering 503 still opens the breaker
--- http_config eval: "$::HttpConfig $::Judge"
--- user_files eval: ::bconf()
--- config eval: "location /v1/chat/completions { $::Access $::Echo }"
--- request eval
[::chat("DOWN please summarise the quarterly figures, first"),
 ::chat("DOWN please summarise the quarterly figures, second"),
 ::chat("SCORE please summarise the quarterly figures once more")]
--- more_headers
Content-Type: application/json
--- response_body eval
["verdict=error score=0.00 source=l2 reason=openai-compat+http+503%3A+down\n",
 "verdict=error score=0.00 source=l2 reason=openai-compat+http+503%3A+down\n",
 "verdict=skipped score=0.00 source=breaker reason=breaker+open\n"]
--- no_error_log
[error]



=== TEST 4: a half-open probe with an unusable answer hands the probe on instead of re-opening
--- http_config eval: "$::HttpConfig $::Judge"
--- user_files eval: ::bconf(1)
--- config eval
"location /v1/chat/completions { $::Access $::Echo }
 location /wait { content_by_lua_block { ngx.sleep(1.1) ngx.say('ok') } }"
--- request eval
[::chat("DOWN please summarise the quarterly figures, first"),
 ::chat("DOWN please summarise the quarterly figures, second"),
 "GET /wait",
 ::chat("please summarise the quarterly figures, the half-open probe"),
 ::chat("SCORE please summarise the quarterly figures once more"),
 ::chat("SCORE please summarise the quarterly figures and again")]
--- more_headers
Content-Type: application/json
--- response_body eval
["verdict=error score=0.00 source=l2 reason=openai-compat+http+503%3A+down\n",
 "verdict=error score=0.00 source=l2 reason=openai-compat+http+503%3A+down\n",
 "ok\n",
 "verdict=error score=0.00 source=l2 reason=unusable%3A+openai-compat%3A+no+content\n",
 "verdict=safe score=0.30 source=l2 reason=injection+0.30\n",
 "verdict=safe score=0.30 source=l2 reason=injection+0.30\n"]
--- no_error_log
[error]
