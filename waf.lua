local content_length=tonumber(ngx.req.get_headers()['content-length'])

local ngxmatch=ngx.re.match

if whiteip() then return end

if blockip() then return end
if is_ban() then return end
if responseErrorProtect() then return end
if denycc() then return end
if ngx.var.http_Acunetix_Aspect then ngx.exit(444) end
if ngx.var.http_X_Scan_Memo then ngx.exit(444) end
if whiteport() then return end
if whiteurl() then return end
if whiteArgs() then return end
if ua() then return end
if url() then return end
if args() then return end
if cookie() then return end

if BodyCheck then
        --设置读取post body体，必须设置，否则无法读取POST数据
      	ngx.req.read_body()
        --POST内容被保存在内存中，用get_body_data直接读
        local data=ngx.req.get_body_data()
        --POST内容太大，被保存到临时文件中，需要以文件方式处理
        --body体大小大于client_body_buffer_size，则会被保存在文件中
        if not data then
            local filePath = ngx.req.get_body_file()
            if filePath then
                local file=io.open(filePath,"r")
                --此处bug：若上传的文件太大超内存，则程序异常，所以nginx中client_max_body_size不能配置太大，否则会撑爆内存
                --若有超大附件上传，则建议添加白名单whiteurl
                data=file:read("*a") 
                file:close()
            end
        end

        if not data then
            --get_body_data和get_body_file都没获取到body，则判定无body数据
            return
        end

        --开始对body数据进行处理
        --查找请求头确定是否存在上传分界符号
        local boundary = get_boundary()

        --存在分界符，进入文件上传处理
        if boundary then
            local parts=split_str(data,boundary)
            for i,v in ipairs(parts) do
                
                local m = ngxmatch(v,[[filename="(.+)\.(.*)"]],'ijo')
                --防上传绕过 
                --畸形上传文件头也会被绕过
                --todo  漏洞:无法解决 a.txt.fff.php 这类绕过
                if not m then
                     m = ngxmatch(v,[[filename=(.+)\.(.*)]],'ijo')
                end
               
                    --如果包含filename，则进行文件后缀名检查
                if m then
                    fileExtCheck(m[2])
                end
                --如果开启了文件上传检测，则进入内容检查
                if PostFileCheck then
                    body(v)
                end
            end
        --不存在分界符，直接进入body检测
        else
            if BodyArgsCheck then
               body(data)
            end
        end
--body check结束
end
