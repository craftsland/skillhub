# Issue #611 验证报告

- Issue：[直接删除版本遗留子表外键并返回 500](https://github.com/iflytek/skillhub/issues/611)
- 状态：本地验证及 `big-main` 远端验证均已通过
- 基线：`origin/main@6817d98007c7890c1a8ecb3e822272287bb37a05`
- 工作分支：`fix/issue-611-child-fks`
- 修复提交：`41704e151e0152cdc7688e5b5baec1df75b02dd7`
- 提交身份：`XiaoSeS <87064762+XiaoSeS@users.noreply.github.com>`
- 已测试的 `big-main` 合并提交：`4bf7d52118a43735240a9be6241d04531bd69cbc`

## 一、判断结论

### 1. 问题是否真实存在

真实存在，而且在 PostgreSQL 16 上可以稳定复现。

基于未修改的 `origin/main`，构造一个包含两个版本的 Skill，其中待删除版本状态为
`REJECTED`，并存在终态 `REJECTED` 审核任务。连续三次调用：

```http
DELETE /api/web/skills/global/issue-611-repro/versions/1.0.0
```

三次均返回 HTTP 500。PostgreSQL 报告 SQL state `23503`：
`review_task_skill_version_id_fkey` 仍引用待删除的 `skill_version`。事务回滚后，版本和审核任务
都还在。作为对照，先删除审核任务再调用同一接口，结果变为 HTTP 200。

### 2. 是否值得修复

值得修复，理由如下：

- 普通用户的版本被拒绝后会自然产生终态审核任务，因此不是异常脏数据。
- 接口明确允许删除 `REJECTED` 版本，但当前实现必然失败。
- 数据库约束异常被暴露成 HTTP 500，而不是可理解的业务结果。
- 删除失败还会阻止用户复用相同版本号。
- 修复可以复用现有的 `ReviewTaskRepository.deleteBySkillVersionIdIn`，改动范围可控。

### 3. 是否需要更大的扩展

不需要引入通用子表清理框架或数据库级级联迁移，但需要补充同一 Skill 的版本聚合锁。

子表处理边界如下：

- `review_task`：必须在删除版本前显式删除该版本的全部审核任务。
- `skill_tag`：正常业务只会引用 `PUBLISHED` 版本，而直接删除接口拒绝该状态。
- `promotion_request`：正常业务只会引用 `PUBLISHED` 来源版本，同样由状态前置条件保护。
- `security_audit`：按设计软删除并保留；V38 已移除其版本外键。
- `skill_file`：原逻辑已经显式删除。
- `skill_version_stats`：数据库使用 `ON DELETE CASCADE`。

并发验证还发现两个相邻问题：

- 两个请求同时删除同一版本时，可能在审核任务的 `@Version` 字段上产生并发异常。
- 两个请求分别删除仅剩的两个版本时，可能同时绕过“至少保留一个版本”约束。

因此，应用服务在选择目标版本前，按版本 ID 顺序对同一 Skill 的全部版本执行
`FOR UPDATE`。这是有 PostgreSQL 实测依据的必要扩展，不是猜测性功能。

## 二、实现说明

1. `SkillGovernanceService.deleteVersion` 在删除 `skill_version` 前删除该版本的全部
   `review_task`。
2. `SkillLifecycleAppService.deleteVersion` 先锁定同一 Skill 的所有版本，再查找目标版本。
3. 锁查询使用按 ID 排序的原生 `FOR UPDATE`：
   - PostgreSQL 能获得稳定的悲观锁顺序。
   - 避免 Hibernate PostgreSQL dialect 生成的 `FOR NO KEY UPDATE` 与 H2 PostgreSQL
     compatibility mode 不兼容。
4. 新增领域服务测试、应用服务锁定测试和持久化 HTTP 集成测试。
5. 保持原接口路径、成功响应结构及业务错误结构不变。

## 三、操作记录

| 时间（UTC+8） | 操作 | 结果 |
|---|---|---|
| 2026-07-30 14:41–14:47 | 在基线代码上使用隔离的 PostgreSQL 16、Redis 7 和 18081 端口复现 | 三次 HTTP 500，确认外键 `23503`；删除审核任务后对照请求为 HTTP 200 |
| 2026-07-30 14:55–15:02 | 拉取 `main`/`big-main`、创建修复分支、检查所有 `skill_version` 外键及生命周期规则 | 确定清理范围，并识别并发删除边界 |
| 2026-07-30 15:02–16:06 | 实现修复并执行单元、集成、PostgreSQL、前端和 staging 验证 | 功能、数据完整性和并发场景通过 |
| 2026-07-30 16:06 | 执行后端回归 | 排除已知污染类后 659 项通过、1 项跳过；被排除类单独 9/9 通过 |
| 2026-07-30 16:08 | 删除本地测试容器、网络、镜像、数据和 staging 临时覆盖 | 清理完成 |
| 2026-07-30 16:16 | 提交并推送工作分支 | 原修复提交 `e7a23b43` |
| 2026-07-30 16:17 | 合入最新 `origin/big-main` 并普通推送 | 合并提交 `43f6d1671949d279ab05720fcddd20a25f0c2607` |
| 2026-07-30 16:18 | 从该 `big-main` worktree 执行 Java 21 干净构建 | 8 个 Maven 模块构建成功 |
| 2026-07-30 16:18–16:38 | 构建首张测试镜像并执行远端矩阵 | 功能矩阵 56/56 通过，但复核时发现 OCI revision 的完整 SHA 后缀记录错误，因此不作为最终证据 |
| 2026-07-30 16:44–16:49 | 使用真实 full SHA 重建 R2 镜像、传输到远端、创建全新隔离栈并重新执行全部场景 | 最终 56/56 通过 |
| 2026-07-30 16:49 | 固化 R2 镜像、脚本、报告哈希及健康状态 | 镜像 revision 与实际 `big-main` commit 完全一致 |
| 2026-07-30 16:50 | 删除 R2 测试容器、网络、卷、镜像、脚本和日志 | 28081 端口关闭；原 8080 服务仍为 `UP` |
| 2026-07-30 17:18 | 将两个 PR 提交重写为 GitHub 账号 `XiaoSeS`，补充 `Signed-off-by` 并使用带精确旧 SHA 的 `force-with-lease` 推送 | 文件树与重写前完全一致；新修复提交为 `41704e15`，DCO 通过 |
| 2026-07-30 17:19 | 将重写后的 PR 提交重新纳入 `big-main` 并普通推送 | 新合并提交为 `4bf7d52118a43735240a9be6241d04531bd69cbc`，相对前一 `big-main` 文件树无变化 |
| 2026-07-30 17:20 | 从新 `big-main` 提交执行 Java 21 干净构建并构建 R3 测试镜像 | 8 个 Maven 模块构建成功；OCI revision 与完整提交 SHA 一致 |
| 2026-07-30 17:23–17:28 | 将 R3 镜像传输到远端测试机，创建全新隔离栈并执行原 56 项矩阵 | PostgreSQL 16.14 上 56/56 通过 |
| 2026-07-30 17:29 | 固化 R3 证据哈希并删除远端测试资源 | 28081 端口关闭；原 8080 服务及 `v0.2.15` 容器保持健康 |

远端传输期间，SFTP 曾停在 0 字节。确认测试尚未开始、数据库中没有测试数据后，仅终止了持有
测试脚本文件的残留 `sftp-server`/`dd` 进程，改用 SSH 命令通道传输，并在执行前校验
SHA-256。没有停止或修改远端既有 SkillHub 服务。

## 四、本地测试报告

### 测试环境

- 基线：`6817d98007c7890c1a8ecb3e822272287bb37a05`
- Java：Eclipse Temurin 21
- 数据库：PostgreSQL 16 Alpine
- Redis：Redis 7 Alpine
- 隔离 API：`127.0.0.1:18081`

### 自动化测试结果

| 检查项 | 结果 |
|---|---|
| `SkillGovernanceServiceTest` | 15/15 通过 |
| 应用生命周期、Controller、持久化定向测试 | 11/11 通过 |
| `SkillVersionDeleteFlowIntegrationTest` | 通过 |
| 前端 TypeScript typecheck | 通过 |
| 前端 ESLint | 通过 |
| 前端 Vitest | 181 个文件、618 项测试全部通过 |
| staging smoke | 15/15 通过 |
| 排除 `ApiTokenAuthenticationFilterTest` 的后端 reactor | 659 项通过、1 项跳过；所有依赖模块成功 |
| `ApiTokenAuthenticationFilterTest` 单独执行 | 9/9 通过 |

### 本地 PostgreSQL 行为验证

- 基线代码：删除带终态审核任务的 `REJECTED` 版本，三次均为 HTTP 500 / SQL state 23503。
- 修复后：HTTP 200，目标版本及其审核任务删除成功。
- 同版本并发：一个 HTTP 200、一个 HTTP 400 `Version not found`，没有 500。
- 不同版本并发：一个 HTTP 200、一个 HTTP 400
  `Cannot delete the last remaining version`，最终恰好保留一个版本。
- 应用日志中没有新增 FK、乐观锁或 stale-state 异常。

### 已知基线问题

1. 默认后端聚合测试存在已有的 `SecurityContext` 污染：
   `ApiTokenAuthenticationFilterTest.shouldIgnoreNonBearerAuthorizationHeader` 会读取其他测试
   遗留的上下文。本次没有修改 auth；该类单独 9/9 通过，其余测试在同一 reactor 中全部通过。
2. 本机 5432 已被无关的 `postgres-local` 占用，因此 staging 使用临时端口覆盖，没有停止该容器。
3. staging web 基线未提供 `SKILLHUB_TRUST_FORWARDED_PROTO`，临时设置为 `false` 后 smoke
   15/15 通过。临时覆盖已删除。

## 五、`big-main` 远端测试报告

### 环境与制品

- 测试机：`47.239.226.166`
- Docker：`29.4.0`
- Docker Compose：`v5.1.1`
- PostgreSQL：`16.14`
- Redis：`redis:7-alpine`
- 已测试提交：`4bf7d52118a43735240a9be6241d04531bd69cbc`
- 最终镜像：`skillhub-server:issue-611-big-main-4bf7d521-r3`
- 最终镜像 ID：
  `sha256:3453a2b21b05d157c7955a2e00c0d90eb771a95c82ddb5490f008a008138de2e`
- OCI revision：`4bf7d52118a43735240a9be6241d04531bd69cbc`
- 构建 JAR SHA-256：
  `4b4a374506cd6ddfd611d10b738e11d08fb94d4238e836781ffd757c03e86e39`
- 测试脚本 SHA-256：
  `455cc712375aa299d3d04bce0c61eafaaf09355faefa303b67ca72e5036fcd76`
- 最终原始测试输出 SHA-256：
  `10c2b26a98d3b52cee6175d03897788ba2bc1f9b3598054ef66cecea79d9e897`
- 隔离 API：`127.0.0.1:28081`

测试部署使用独立容器名、网络、PostgreSQL 数据卷、对象存储卷和端口，不替换远端既有运行环境。
R3 是修正提交身份和 DCO 后的最终验证制品；其完整测试矩阵与 R2 相同，测试脚本哈希也保持一致。

### 并发测试隔离说明

本次 R3 使用 `skillhub-611-r3-4bf7d521-*` 作为资源前缀，并在创建资源前检查容器名、网络、
数据卷和 `127.0.0.1:28081` 是否已占用。发生冲突时测试会退出，不会接管或删除已有资源。
测试前后均确认远端既有 `ghcr.io/iflytek/skillhub-server:v0.2.15` 容器在 8080 端口保持
`running`、`healthy` 和 `{"status":"UP"}`。

固定的 28081 端口只能避免破坏，不能支持多个 Issue 同时运行。后续远端验证需要采用以下并发规则：

- 每次测试生成包含 Issue、精确提交和随机后缀的唯一 run ID。
- 由 Docker 自动分配仅绑定回环地址的临时端口，启动后读取实际端口传给测试脚本。
- 容器、网络、数据卷、镜像和临时文件全部携带 run ID；清理只按该 run 精确执行。
- 禁止在共享测试机执行 `docker system prune`、宽泛名称匹配或未指定项目名的全局清理。
- `big-main` 更新必须先 fetch 并使用普通 push；远端头变化时重新合并并生成新的待测 SHA。
- 测试报告必须记录精确的 `big-main` SHA、镜像 ID、OCI revision、动态端口和测试输出哈希。

### 测试矩阵

| 类别 | 场景 | 预期 | 结果 |
|---|---|---|---|
| 核心回归 | 删除带终态审核任务的非最后 `REJECTED` 版本 | HTTP 200，版本和其审核任务删除 | 通过 |
| 正常路径 | 删除非最后 `DRAFT`、`UPLOADED`、`SCAN_FAILED` 版本 | HTTP 200，保留其他版本 | 通过 |
| 多子记录 | 同一版本存在 `REJECTED`、`APPROVED` 两条历史任务 | 目标版本的审核任务全部删除 | 通过 |
| 跨版本隔离 | 另一版本有独立审核任务 | 另一版本及任务保持不变 | 通过 |
| 最后版本 | 删除仅剩的 `REJECTED` 版本 | 业务 400，所有数据和存储保持不变 | 通过 |
| 状态保护 | 删除被 tag、promotion、latestVersion 引用的 `PUBLISHED` 版本 | 业务 400，引用保持不变 | 通过 |
| 状态保护 | 删除 `YANKED` 版本 | 业务 400，版本不变 | 通过 |
| 权限/可见性 | 非所有者删除其他用户的版本 | owner-scoped 解析返回确定性业务 400，零变更 | 通过 |
| 审计保留 | 待删版本存在 `security_audit` | 版本删除，审计软删除后保留 | 通过 |
| 文件完整性 | 待删版本有 `skill_file`、文件对象和 bundle | 提交后数据库和对象存储均清理 | 通过 |
| 统计数据 | 待删版本有 `skill_version_stats` | 目标统计级联删除，其他版本统计保留 | 通过 |
| 版本复用 | 删除后重新创建相同版本号 | 唯一键释放，可重新创建 | 通过 |
| 重复请求 | 成功删除后再次删除 | 确定性业务 400，保留版本不变 | 通过 |
| 同版本并发 | 两个请求同时删除同一版本 | HTTP 200 + 400，无 500、无孤儿数据 | 通过 |
| 不同版本并发 | 两个请求分别删除仅剩的两个版本 | HTTP 200 + 400，最终恰好保留一个版本 | 通过 |
| 回滚 | 前置条件或权限检查拒绝删除 | 数据、存储、审核任务不变，不写删除审计 | 通过 |
| 响应兼容 | 校验成功响应字段 | `code=0`、`action=DELETE_VERSION` 等字段不变 | 通过 |
| 服务稳定性 | 完整矩阵后检查健康和异常日志 | 服务 `UP`，无相关异常 | 通过 |

最终测试脚本种植了 10 个隔离 Skill、19 个版本，共执行 56 个断言：

```text
summary_pass=56 summary_fail=0
```

六次成功删除恰好产生六条 `DELETE_SKILL_VERSION` 审计记录。测试结束时没有
`review_task` 孤儿记录。应用日志未出现以下异常：

```text
ConstraintViolationException
DataIntegrityViolationException
ObjectOptimisticLockingFailureException
StaleObjectStateException
StaleStateException
```

非所有者场景最初按 HTTP 403 设计，但真实接口会先按当前用户范围解析坐标，因此返回 HTTP 400：

```text
Skill not found: issue-611-permission
```

确认版本和审核任务均未改变后，将验收要求修正为“确定性业务 4xx 且零变更”，并使用全新数据库
重跑完整矩阵。

### 清理与回滚

- 删除测试 API、PostgreSQL、Redis 三个容器。
- 删除测试网络、PostgreSQL 卷、对象存储卷。
- 删除测试镜像、临时测试脚本和原始日志。
- 确认 `127.0.0.1:28081` 不再监听。
- 确认远端原有 `127.0.0.1:8080` 服务仍返回 `{"status":"UP"}`。

## 六、剩余风险

- 聚合锁使用 PostgreSQL/H2 可执行的原生 SQL；未来若增加其他数据库实现，需要提供等价的稳定
  悲观锁语义。
- 默认后端聚合测试仍可能被仓库已有的 auth `SecurityContext` 污染影响，与本修复无关。
- 远端 API 使用 local mock-auth profile 来稳定验证 owner/non-owner 行为；本改动不涉及 OAuth，
  因此没有重复验证 OAuth 登录。
