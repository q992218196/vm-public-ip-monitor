# Laravel 采集与分析服务

此目录只运行 Agent 上报、截图 worker 任务、告警分析和维护命令。管理登录、账号、节点、网站和告警页面由 `admin/` 中的 BuildAdmin 提供；这里没有管理页面或登录路由。

正式部署请使用仓库根目录的 `docs/DEPLOYMENT.md` 和 `deploy/compose.yml`、`deploy/compose.buildadmin.yml`。不要单独把 Laravel Web 容器暴露到公网；公网入口仅将 `/api/v1/*` 代理给它。

保留 PostgreSQL 中的历史 `users` 表，供已有安装的一次性 BuildAdmin 账号导入及历史数据追溯。移除管理页面不需要删除监控数据或历史账号记录。