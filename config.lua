RulePath = "/www/waf/wafconf/"
attacklog = "on"
logdir = "/www/waf/logs/"
UrlDeny="on"
Redirect="on"
CookieMatch="on"
postMatch="on"
whiteModule="on"
black_fileExt={"php","jsp"}
ipWhitelist={"127.0.0.1"}
ipBlocklist={"1.0.0.1"}
CCDeny="on"
CCrate="300/60"
---自定义值，获取真实IP的请求头，在CDN或前置代理中自定义配置的值
---为什么不用固定值？答：防止恶意构造请求头，造成特定的拒绝服务攻击
---举例：前置CDN配置请求头X-FORWARDED-FOR，则此处配置HTTP_X_FORWARDED_FOR
HTTP_X_FORWARDED_FOR_HEADER="HTTP_X_FORWARDED_FOR"
---是否封锁攻击源
BanIp="on"
---每次攻击扣减分数
BanGradePeerAttack=25
---总分数，当攻击总扣减分数超过该值，将触发源IP封堵
---BanGradePeerAttack和BanTotalGrade配合用以控制封锁策略
BanTotalGrade=100
---封锁IP 时间,单位 秒
BanTime="3600"

--是否检测POST 文件,检测可能导致网页、代码等文件上传失败
checkPostFile="on"
--是否检测POST args
checkPostArgs="on"


