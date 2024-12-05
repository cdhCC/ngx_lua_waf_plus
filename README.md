# ngx_lua_waf_plus

基于loveshell/ngx_lua_waf，做了部分调整

参考 https://github.com/loveshell/ngx_lua_waf

申明：由于架构原因，本waf天然存在许多可被绕过的漏洞，建议启用攻击封锁，在被探测出绕过方式前封锁探测IP。
封锁攻击IP，实乃无奈之举。
预算充足建议上商用waf。


加载方式
在nginx.conf的server块中加入如下配置


lua_package_path "/www/waf/?.lua;";

lua_shared_dict banip 10m;

lua_shared_dict cclimit 10m;

lua_shared_dict resErrLimit 10m;

init_by_lua_file  /www/waf/init.lua;

access_by_lua_file /www/waf/waf.lua;

log_by_lua_file /www/waf/response.lua;

