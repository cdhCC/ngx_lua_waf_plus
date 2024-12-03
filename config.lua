RulePath = "/www/waf/wafconf/"
attacklog = "on"
logdir = "/www/waf/logs/"
UrlDeny="on"
Redirect="on"
CookieMatch="on"
whiteModule="on"
black_fileExt={"php","jsp"}
ipWhitelist={"127.0.0.1"}
ipBlocklist={"1.0.0.1"}
CCDeny="on"
CCrate="300/60"
---自定义值，获取真实IP的请求头，在CDN或前置代理中自定义配置的值
---为什么不用固定值？答：防止恶意构造请求头，造成特定的拒绝服务攻击
---举例：前置CDN配置请求头X-FORWARDED-FOR，则此处配置HTTP_X_FORWARDED_FOR
HTTP_X_FORWARDED_FOR_HEADER="HTTP_X_FORWARDED_FOR_dfx1"
---是否封锁攻击源
BanIp="on"
---每次攻击扣减分数
---统计攻击分数而不是统计攻击次数原因：方便后期扩展，不同攻击扣减不同分数，攻击扣减分数差异化设计
BanGradePeerAttack=30
---总分数，当攻击总扣减分数超过该值，将触发源IP封堵
---BanGradePeerAttack和BanTotalGrade配合用以控制封锁策略
BanTotalGrade=100
---封锁IP 时间,单位秒
BanTime="1200"

BodyCheck="on"
--是否检测POST 文件,文件上传检测可能导致网页、代码等文件上传失败，出现误封等情况
PostFileCheck="on"
--是否检测POST args
BodyArgsCheck="on"

---是否进行检测响应状态码监控
---防扫描，当客户端大批量访问出现404或其他错误状态码，则该客户端大概率是在做站点扫描
---启用该功能需注意，后端业务要处于正常状态，不能出现大量页面不能访问，否则将会误杀正常业务
responseErrorProtect="on"
---异常响应状态码检测类型
responseErrorType={404}
---错误响应次数，在checktime时间内发生 Count 次异常响应记录即视为异常，封锁源IP ErrorBanTime 秒
responseErrorCount=10
---错误检测时间区间 单位 秒
responseErrorCheckTime=60
---错误检测异常保护时间，单位：秒，发生封锁后，解锁时间
responseErrorBanTime=1200
