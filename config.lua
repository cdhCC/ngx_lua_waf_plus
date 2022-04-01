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
---是否封锁攻击源
BanIp="on"
---每次攻击扣减分数
BanGradePeerAttack=15
---总分数，当攻击总扣减分数超过该值，将触发源IP封堵
---BanGradePeerAttack和BanTotalGrade配合用以控制封锁策略
BanTotalGrade=100
---封锁IP 时间 单位 秒
BanTime="3600"
