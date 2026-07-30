# args-paper-site

`dao-genesis/ARGs-Paper`（私有主仓）`docs/` 的**公开加密镜像**，由 GitHub Pages 对外发布。

**公网地址：https://dao-genesis.github.io/args-paper-site/** （访问口令 `dao`）

## 两仓联动（锁定架构）
- **私有主仓 `dao-genesis/ARGs-Paper`**：论文源 + 生成器；`docs/` 站点产物的产地。
- **本公开仓 `args-paper-site`**：只承载可公开的静态产物，GitHub Pages 从这里发布。
- 根因：主仓 free 套餐无法对外开 Pages/Actions；故解耦。页面口令门控 + noindex，`content.enc`/`figures.enc`/`minpack.enc` 为 AES-256-GCM（PBKDF2-SHA256 200k）加密，`data.json` 为可公开进度总览；明文稿件/数据永不外泄。

## 自动同步（勿手改）
- 工作流 `.github/workflows/pull-and-sync.yml` **每 10 分钟 + 手动 `workflow_dispatch`**，从主仓 **`master`** 的 `docs/` 拉取固定文件清单并提交到本仓 `main`，Pages 自动重建。
- 需要本仓 Secret **`PRIVATE_SRC_TOKEN`**（对 `ARGs-Paper` 有 `contents:read` 的 PAT）。
- ⚠️ **本仓内容由同步覆盖，请勿手改站点产物**；一切站点改动走主仓 `docs/` → 合并进 `master`。**PR 分支上的改动不会上线。**
- 完整说明见主仓 `docs/_SITE_ARCHITECTURE_两仓联动.md`。

当前版本：**v64**（随主仓 `master` 自动同步；站点最小包 14 项，含稿件 PDF / 补充表三线表 docx / 亮点 docx / 图集 PDF）。
