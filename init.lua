require 'config'
local match = string.match
local ngxmatch=ngx.re.find
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir 
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
BodyCheck = optionIsOn(BodyCheck)
PostFileCheck=optionIsOn(PostFileCheck)
BodyArgsCheck=optionIsOn(BodyArgsCheck)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny) 
Redirect=optionIsOn(Redirect)
BanIp=optionIsOn(BanIp)
responseErrorProtect=optionIsOn(responseErrorProtect)

---todo 此处存在BUG，如果攻击者在头部伪造HTTP_X_FORWARDED_FOR字段，能对被伪造的IP造成拒绝服务攻击
---解决办法1：只允许来自特定remote_addr主机的数据包更换IP为HTTP_X_FORWARDED_FOR，需要用户手动配置前端代理IP
---解决办法2：只允许包含自定义请求头的数据包更换IP
function getClientIp()
        IP  = ngx.var.remote_addr 
        ---针对前面有代理的情况 返回值可能存在多个IP： 代理1,代理2,代理3
        ---if ngx.var.HTTP_X_FORWARDED_FOR then
        ---    IP = ngx.var.HTTP_X_FORWARDED_FOR
        ---end
        ---针对前面有N个代理的情况，需要前面代理配置X-REAL-IP，一般只有一个IP
        ---if ngx.var.HTTP_X_REAL_IP then
        ---    IP = ngx.var.HTTP_X_REAL_IP
        ---end
        ---采用方法2, X_FORWARDED_FOR_HEADER 参数在config中配置，是自定义的代理请求头
        if ngx.var[HTTP_X_FORWARDED_FOR_HEADER] then
            IP = ngx.var[HTTP_X_FORWARDED_FOR_HEADER]
        end

        if IP == nil then
                IP  = "unknown"
        end
        return IP
end


function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(method,url,data,ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end

function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
wturirules=read_rule('whiteuri')
wtportrules=read_rule('whiteport')
postrules=read_rule('post')
ckrules=read_rule('cookie')
returnhtml=read_rule('returnhtml')
banhtml=read_rule('banhtml')



function ban_ip(point)
    local token = getClientIp() .. "_BAN"
    local limit = ngx.shared.banip
    local req,_=limit:get(token)
    if req then
        limit:set(token,req+point,tonumber(BanTime),ngx.time())  --发现一次，增加积分，BANTIME内有效
    else
        limit:set(token,point,tonumber(BanTime),ngx.time())
    end
end

function get_ban_times()
    local token = getClientIp() .. "_BAN"
    local limit = ngx.shared.banip
        local req,_=limit:get(token)
    if req then
	---log('limit:get',req,"-","get_ban_times")
        return req
    else 
        return 0
    end
end

---检查源IP是否被Ban，如果被ban，则返回封锁页面
function is_ban()
    if BanIp then
        if get_ban_times() >= BanTotalGrade then        --超过规定的BanTotalGrade积分，封锁IP，从上一次攻击被扫描到开始计算，总计封锁 BanTime 秒
	    log('多次攻击BAN-IP:  ',ngx.var.request_uri,"-","BLOCK_IP")
            ngx.status = ngx.HTTP_FORBIDDEN
	    ngx.header.content_type = "text/html;charset=UTF-8"
	    ngx.say("<div style='display: none;'>" .. ngx.localtime() .. "</div>")
	    ngx.say("<div style='display: none;'> HELLO, " .. getClientIp() .. " , YOU HAVE BEEN BLOCKED BY US, TRY ANOTHER DAY ! SORRY ! BYE</div>")
            ngx.say(banhtml)
            ngx.exit(ngx.HTTP_FORBIDDEN)
            return true
        else
            return false
        end
    end
    return false
end

function checkResponseStatus(state)
    for _,errtype in pairs(responseErrorType) do
            if state == errtype then
                add_responseError(1)
		log('异常状态检测  ' .. errtype ,ngx.var.request_uri,"-","RESPONSE_ERROR")
            end
    end
end

function add_responseError(point)
    local token = getClientIp() .. "_errResponse"
    local limit = ngx.shared.resErrLimit
    local req,_=limit:get(token)
    if req then
        limit:set(token,req+point,tonumber(responseErrorCheckTime),ngx.time())
    else
        limit:set(token,point,tonumber(responseErrorCheckTime),ngx.time())
    end
end


---获取响应状态码错误次数
function get_responseError()
    local token = getClientIp() .. "_errResponse"
    local limit = ngx.shared.resErrLimit
        local req,_=limit:get(token)
    if req then
        return req
    else
        return 0
    end
end

---检查源IP是否发生多次响应异常状态，如果次数太多，则封锁 responseErrorBanTime 秒
function responseErrorProtect()
    if responseErrorProtect then
	local responseError = get_responseError()
        if responseError >= responseErrorCount then
	    ---达到检测阈值，进行长时间封锁
	    if responseError == responseErrorCount then
	        local token = getClientIp() .. "_errResponse"
		local limit = ngx.shared.resErrLimit
		limit:set(token,responseErrorCount+1,tonumber(responseErrorBanTime),ngx.time())
	    end

            log('异常状态封禁  ',ngx.var.request_uri,"-","TOMANY_RESPONSE_ERROR")
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = "text/html;charset=UTF-8"
            ngx.say("<div style='display: none;'>" .. ngx.localtime() .. "</div>")
            ngx.say("<div style='display: none;'> HELLO, " .. getClientIp() .. " , YOUR REQUEST HAVE TO MUCH ERROR RESPONSE,PLEASE TRY ANOTHER TIME ! SORRY</div>")
            ngx.say(banhtml)
            ngx.exit(ngx.HTTP_FORBIDDEN)
            return true
        else
            return false
        end
    end
    return false
end



--发现一次攻击扣BanGradePeerAttack分，超过BanTotalGrade分直接封锁源IP
function BanAndRuturnHtml()
    ban_ip(BanGradePeerAttack)
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
	    ngx.say("<div style='display: none;'>" .. ngx.localtime() .. "</div>")
	    ngx.say("<div style='display: none;'>" .. getClientIp().. " BLOCKED!</div>")
        ngx.say(returnhtml)
        ngx.exit(ngx.status)
    end
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end

function whiteuri()
    if WhiteCheck then
        local args=ngx.var.arg_service
        if args == nil then
           return false
        end
        if wturirules ~=nil then
            for _,rule in pairs(wturirules) do
                if ngxmatch(args,rule,"isjo") then
                    return true
                 end
            end
        end
    end
    return false
end

function whiteport()
    if WhiteCheck then
        local args=ngx.var.server_port
        if args == nil then
           return false
        end
        if wtportrules ~=nil then
            for _,rule in pairs(wtportrules) do
                if ngxmatch(args,rule,"isjo") then
                    return true
                 end
            end
        end
    end
    return false
end


function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext,rule,"isjo") then
	        log('FileExt_Check',ngx.var.request_uri,"-","file attack with ext "..ext)
            BanAndRuturnHtml()
            end
        end
    end
    return false
end

function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end

function args()
    local args = ngx.req.get_uri_args()
    local uri=ngx.var.request_uri()

    --todo : 漏洞  ngx.req.get_uri_args()只能获取100个参数，超过100造成绕过漏洞
    for _,rule in pairs(argsrules) do
        
        for key, val in pairs(args) do
            if type(val)=='table' then
                 local t={}
                 for k,v in pairs(val) do
                    if v == true then
                        v=""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                log('Args_Check',uri,"-",rule)
                BanAndRuturnHtml()
                return true
            end
        end
        
         --临时修复
        if rule ~="" and ngxmatch(uri,rule,"isjo") then
            log('Args_Check',uri,"-",rule)
                BanAndRuturnHtml()
                return true
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('URL_Check',ngx.var.request_uri,"-",rule)
                BanAndRuturnHtml()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                log('UA_Check',ngx.var.request_uri,"-",rule)
                BanAndRuturnHtml()
                return true
            end
        end
    end
    return false
end

function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
            log('Body_Check',ngx.var.request_uri,data,rule)
            BanAndRuturnHtml()
            return true
        end
    end
    return false
end

function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                log('Cookie_Check',ngx.var.request_uri,"-",rule)
                BanAndRuturnHtml()
            return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.cclimit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                 ngx.exit(444)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
    return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(444)
                 return true
             end
         end
     end
         return false
end


function split_str(str, sep)
    local t={}
    local _start=0;
    local _end=0;
    local last_end=_end;
    while true do
        _start,_end=string.find(str,sep,last_end+1)
        if _start ~= nil and _end ~=nil then
                if _start ~= last_end+1 then
                        table.insert(t,string.sub(str,last_end+1,_start-1))
                end
                last_end=_end
        else
                table.insert(t,string.sub(str,last_end+1,string.len(str)))
                break
        end
    end
    return t;
end
