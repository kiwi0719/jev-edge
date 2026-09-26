use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

# openai-compat reply parsing under the real cjson (the busted spec stands dkjson
# in for it): spec/openai_compat_vectors.json, which the TS provider replays too.
my $pwd = cwd();
our $Vectors = "$pwd/spec/openai_compat_vectors.json";
our $HttpConfig = qq{ lua_package_path "$pwd/lib/?.lua;$pwd/../../?.lua;;"; };

plan 'no_plan';
workers(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: every row of openai_compat_vectors.json gives its answers or its error
--- http_config eval: $::HttpConfig
--- config eval
qq{
location = /t {
    content_by_lua_block {
        local cjson = require "cjson.safe"
        local P = require "resty.jev.providers.openai_compat"
        local f = assert(io.open("$::Vectors"))
        local V = assert(cjson.decode(f:read("*a")))
        f:close()
        local bad = 0
        for _, r in ipairs(V.rows) do
            local function nest(s)
                if not s or not r.nest then return s end
                return (s:gsub("\@NEST\@", function() return string.rep("[", r.nest) .. string.rep("]", r.nest) end))
            end
            local wanted = {}
            for _, q in ipairs(r.questions or { "injection" }) do wanted[q] = true end
            local body = r.body or cjson.encode({ choices = { { message = { content = nest(r.reply) } } } })
            local got, err = P.parse_response(200, body, {}, { questions = wanted, text = nest(r.text) or "" })
            local ok
            if r.want == "error" then
                ok = got == nil
            else
                ok = type(got) == "table"
                for k, v in pairs(r.want) do
                    ok = ok and type(got[k]) == "number" and math.abs(got[k] - v) < 1e-12
                end
                for k in pairs(got or {}) do ok = ok and r.want[k] ~= nil end
            end
            if not ok then
                bad = bad + 1
                ngx.say(r.name, ": got ", got and cjson.encode(got) or ("error " .. tostring(err)))
            end
        end
        ngx.say(#V.rows, " rows, ", bad, " wrong")
    }
}
}
--- request
GET /t
--- response_body_like
^\d+ rows, 0 wrong$
--- no_error_log
[error]
