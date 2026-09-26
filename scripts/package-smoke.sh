#!/bin/sh
# The rock and the opm tree as users install them, each loaded on its own
# (scripts/require-all.lua) with cwd outside the checkout, so ./?.lua cannot
# stand in for a module the package failed to install. Runs in the
# jev-edge-test image, which has luarocks, make, resty and lua-resty-http:
#
#   docker run --rm -v "$PWD":/work:ro -w /tmp jev-edge-test sh /work/scripts/package-smoke.sh
#
# (`make package-check`). Writes only under /tmp.
set -eu

rockspec=$(ls /work/lua-resty-jev-edge-*.rockspec)
rm -rf /tmp/rock /tmp/dist
(cd /work && luarocks make --tree /tmp/rock --deps-mode none "$rockspec") > /tmp/luarocks.log 2>&1 \
  || { cat /tmp/luarocks.log; exit 1; }
make -s -C /work dist DIST=/tmp/dist/pkg > /dev/null

cd /tmp
resty /work/scripts/require-all.lua "$rockspec" /tmp/rock/share/lua/5.1
resty /work/scripts/require-all.lua "$rockspec" /tmp/dist/pkg/lib --no-kong
