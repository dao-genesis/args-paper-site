# args-paper-site

`dao-genesis/ARGs-Paper` 私有主仓 `docs/` 的**公开加密镜像**，由 GitHub Pages 托管。

- 页面口令门控 + noindex；`content.enc` / `minpack.enc` 为 AES-256-GCM（PBKDF2-SHA256 200k）加密，`data.json` 为可公开进度总览。
- 源与生成脚本在私有主仓 `docs/_build_site.py`；本仓仅承载静态产物，随主仓 v 版本更新。
- 当前版本：v58（Manuscript_v57 · 内嵌 TNR 新图 · GA 重设计）。
