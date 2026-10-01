# Laravel 采集与分析服务

此目录只运行 Agent 上报、截图 worker 任务、告警分析和维护命令。管理登录、账号、节点、网站和告警页面由 `admin/` 中的 BuildAdmin 提供；这里没有管理页面或登录路由。

正式部署请使用仓库根目录的 `docs/DEPLOYMENT.md` 和 `deploy/compose.yml`、`deploy/compose.buildadmin.yml`。不要单独把 Laravel Web 容器暴露到公网；公网入口仅将 `/api/v1/*` 代理给它。

采集服务不包含管理账号模型、登录／会话路由或账号导入工具。全新数据库只创建监控业务表和队列／缓存表；现有安装中的历史账号表不会被自动删除，也不再供任何登录入口使用。BuildAdmin 管理账号独立存于 MySQL。
