# Demo image: stock OpenResty plus lua-resty-http. The repo is mounted at
# /work by docker-compose.yml, so no install step and no copy of the tree.
FROM openresty/openresty:alpine-fat
RUN opm get ledgetech/lua-resty-http
RUN mkdir -p /tmp/nx/logs
CMD ["openresty", "-p", "/tmp/nx", "-c", "/tmp/nx/conf/nginx.conf", "-g", "daemon off;"]
