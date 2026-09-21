# Shared prelude for jev-edge Test::Nginx suites.
use Cwd qw(cwd);

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/../../?.lua;;";
    lua_shared_dict jev_cache   8m;
    lua_shared_dict jev_config  1m;
    lua_shared_dict jev_metrics 1m;
    lua_shared_dict jev_subject 1m;

    init_by_lua_block {
        require("resty.jev.edge").init("$pwd/t/servroot/html/jev-edge.conf.lua")
    }
    init_worker_by_lua_block { require("resty.jev.edge").init_worker() }
};

# Echo upstream: prints the X-Jev-* headers the gateway attached.
our $Echo = q{
    content_by_lua_block {
        local h = ngx.req.get_headers()
        ngx.say("verdict=", h["x-jev-verdict"] or "-",
                " score=", h["x-jev-score"] or "-",
                " source=", h["x-jev-source"] or "-",
                " reason=", h["x-jev-reason"] or "-")
    }
};

our $Access = q{ access_by_lua_block { require("resty.jev.edge").access() } };

# Timers (reload every 2s) would otherwise delay graceful shutdown between blocks.
Test::Nginx::Socket::Lua::add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value("main_config", "worker_shutdown_timeout 300ms;");
});

sub conf {
    my ($extra) = @_;
    $extra //= "";
    return qq{
>>> jev-edge.conf.lua
return {
  jev = { provider = "mock", mock_header = "x-jev-mock-score", mock_score = 0.1, timeout_ms = 300 },
  rules = { "llm-endpoints" },
  policy = { mode = "monitor", block_threshold = 0.85, suspect_threshold = 0.5 },
  async = { enabled = true, max_async = 8, rep_block_after = 1, rep_block_ttl = 60 },
  breaker = { window_s = 60, min_samples = 2, fail_ratio = 0.5, open_s = 30 },
  $extra
}
};
}

1;
