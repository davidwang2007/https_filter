# ssl port forward

# self signed certificate, to filter the ssl content

# 比如想监控 https://www.baidu.com 的请求内容，则 --target 参数指定 www.baidu.com:443

# 并且在 hosts 文件中加上 127.0.0.1 work.thed3chain.com, 则是先请求本地，由本地转发至远程，拦截的记录在 --log 文件指定的内容中
