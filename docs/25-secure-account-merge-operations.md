# 安全账号合并运维与发布手册

> 适用范围：Issue [#662](https://github.com/iflytek/skillhub/issues/662) 的安全账号合并实现。
>
> 安全与验收规则以
> [`22-secure-account-merge-acceptance-design.md`](./22-secure-account-merge-acceptance-design.md)
> 为准；本文件只定义如何部署、启用、观察和回滚。

## 1. 发布边界

账号合并默认关闭。两个条件同时满足时，新流程才可用：

```text
SPRING_SESSION_REDIS_REPOSITORY_TYPE=indexed
SKILLHUB_AUTH_ACCOUNT_MERGE_SESSION_CUTOVER_COMPLETE=true
SKILLHUB_AUTH_ACCOUNT_MERGE_ENABLED=true
```

应用在功能开启但 Spring Session 不是 indexed repository，或没有确认 Session namespace
切换完成时拒绝启动。Helm 在对应条件不满足时也拒绝渲染。

以下三个旧接口无论开关状态如何都保持 `503 Service Unavailable`，不能作为回滚或兼容
入口：

```text
POST /api/v1/account/merge/initiate
POST /api/v1/account/merge/verify
POST /api/v1/account/merge/confirm
```

不要删除、改写或手工完成旧 `account_merge_request`。新流程只使用
`account_merge_intent` 和服务端 Session proof。

## 2. Redis 前置条件

### 2.1 Principal index

Spring Session 用 `PlatformPrincipal#getName()` 的稳定平台 `userId` 建立 principal index。
合并完成后，后台任务用该 index 找到并删除次账号的全部 Session。账号状态守卫会在每个
API 请求重新读取 `user_account`，所以 Redis 删除重试期间，已标记 `MERGED` 的账号也会
立即收到 401。

`default` 与 `indexed` repository 使用兼容的 Session hash key，因此 indexed repository
能读取旧 Session；但真实 Redis 验证表明，旧 repository 创建的 Session 即使更新
last-accessed 并再次保存，也不会自动补入 principal index。它会被当作“索引已经存在”
处理。旧 Session 因而不能被后台任务枚举。

安全升级必须更换 `SESSION_REDIS_NAMESPACE`，让所有旧 Session 一次性失效；不能依赖
访问预热、在线 Session 抽样或等待 TTL。模板为本次切换使用
`skillhub:session:indexed-v1`。如果现有部署已占用该 namespace，必须选择一个从未使用的
新值。

### 2.2 Keyspace notification

模板默认：

```text
SPRING_SESSION_REDIS_CONFIGURE_ACTION=notify-keyspace-events
```

这允许 Spring Session 配置所需的 Redis keyspace notification。托管 Redis 如果禁止
`CONFIG`，必须先由运维平台配置相应通知，再使用：

```text
SPRING_SESSION_REDIS_CONFIGURE_ACTION=none
```

不能仅为了让应用启动而设为 `none`；必须先在目标 Redis 拓扑完成 Session 创建、按
principal 查询、过期和删除验证。Redis Cluster 还必须运行仓库中的
`RedisClusterIntegrationTest`，不能用单机 Redis 结果替代。

## 3. 两阶段启用

### 阶段 A：切换 Session namespace

1. 备份 PostgreSQL，并记录当前镜像和旧 `SESSION_REDIS_NAMESPACE`。
2. 确认网关精确阻断三个旧接口；不要阻断新的 `/intents` 和 `/reauthenticate` 资源。
3. 选择一个本部署从未使用、且不与其他环境共享的新 namespace，部署所有新 Pod：

   ```text
   SESSION_REDIS_NAMESPACE=skillhub:session:indexed-v1
   SPRING_SESSION_REDIS_REPOSITORY_TYPE=indexed
   SKILLHUB_AUTH_ACCOUNT_MERGE_SESSION_CUTOVER_COMPLETE=false
   SKILLHUB_AUTH_ACCOUNT_MERGE_ENABLED=false
   ```

4. 确认没有仍读写旧 namespace 的 Pod。切换会让现有 Web Session 全部退出，这是预期
   的一次性安全迁移。
5. 重新登录，验证普通本地/OAuth/CAS 登录、`/api/v1/auth/me`、API Token、Namespace
   和 Skill 访问。
6. 在目标 Redis 拓扑创建至少两个 Session，确认可用稳定 userId 通过 principal index
   找到，并验证删除、失败重试和最终清空。运行仓库中的真实 Redis 集成测试。
7. 使用已登录 Session 请求 `GET /api/v1/account/merge/capabilities`，确认
   `data.enabled=false`。
8. 上述项目全部通过后，才把
   `SKILLHUB_AUTH_ACCOUNT_MERGE_SESSION_CUTOVER_COMPLETE` 视为可设置为 `true`。

旧 namespace 可以先保留到原 TTL 自然过期。若需要清理，只能在备份并确认未被其他环境
共享后删除旧 namespace 的精确 keys；禁止 `FLUSHDB`、`FLUSHALL` 或宽泛 key 删除。

### 阶段 B：启用新流程

1. 保持阶段 A 的新 Redis namespace 和 `indexed` repository。
2. 同时设置：

   ```text
   SKILLHUB_AUTH_ACCOUNT_MERGE_SESSION_CUTOVER_COMPLETE=true
   SKILLHUB_AUTH_ACCOUNT_MERGE_ENABLED=true
   ```

   然后滚动部署所有 Pod。
3. 确认没有关闭功能的旧 Pod；混跑会导致请求随机得到不可用结果。
4. 使用已登录 Session 请求 capabilities，确认 `data.enabled=true` 且认证方法与已启用
   Provider 一致。
5. 在测试账号上完成双账号验证矩阵：主/次账号分别重新认证、preview、confirm、次账号
   Session 401、次账号 Token 401、主账号 Session/Token 正常。
6. 检查 `account_merge_session_revocation` 没有长期停留的 `PENDING`/`PROCESSING`
   任务，并检查账号合并及 Session 撤销重试指标。

Docker Compose 对应：

```text
SESSION_REDIS_NAMESPACE=skillhub:session:indexed-v1
SPRING_SESSION_REDIS_REPOSITORY_TYPE=indexed
SPRING_SESSION_REDIS_CONFIGURE_ACTION=notify-keyspace-events
SKILLHUB_AUTH_ACCOUNT_MERGE_SESSION_CUTOVER_COMPLETE=false|true
SKILLHUB_AUTH_ACCOUNT_MERGE_ENABLED=false|true
```

Helm 对应：

```yaml
session:
  redisNamespace: skillhub:session:indexed-v1
  repositoryType: indexed
  configureAction: notify-keyspace-events
auth:
  accountMerge:
    enabled: false # 阶段 B 才改为 true
    sessionCutoverComplete: false # 阶段 B 验收通过后才改为 true
```

Kustomize base 对应 ConfigMap keys：

```text
session-redis-namespace
session-repository-type
session-redis-configure-action
auth-account-merge-enabled
auth-account-merge-session-cutover-complete
```

## 4. 升级兼容性

- Flyway V50 只新增表、索引和约束；不删除旧表或旧字段。
- `PlatformPrincipal` 的 record 字段和 Java 序列化数据保持不变，只新增稳定
  `Principal#getName()` 行为。
- 旧 Session hash 可由 indexed repository 读取，但不会可靠补建 principal index；阶段 A
  必须通过新 namespace 让它们失效。
- 旧 `account_merge_request` 只保留审计事实，不能转换为新 intent。
- 新旧 Pod 共存期间功能必须关闭；所有新 Pod 就绪且旧 Session 收敛后再启用。
- 已完成的合并不可自动拆分，不能把镜像或数据库 schema 回滚等同于账号恢复。

## 5. 关闭与回滚

### 5.1 只关闭功能

先设置 `SKILLHUB_AUTH_ACCOUNT_MERGE_ENABLED=false` 并完成全部 Pod 滚动。关闭后：

- 不能创建、认证、预览或确认新 intent。
- 已完成合并保持有效。
- 未完成 intent 保留为审计数据，并按其原有 TTL 失效；不要手工改为完成。
- 继续保留 indexed Session 配置、V50 表和每请求账号状态守卫。

### 5.2 回滚应用镜像

1. 先在网关阻断整个 `/api/v1/account/merge/*`，再启动可能包含旧不安全流程的镜像。
2. 不回滚或删除 V50 schema；additive 表可以由旧应用忽略。
3. 不把 `MERGED` 次账号改回 `ACTIVE`，不恢复已撤销 Token，不复制或重绑凭据。
4. 如确需拆分账号，必须走独立、人工审核、带备份和数据清单的数据恢复流程。
5. 回滚完成后验证普通登录、Token、Namespace、Skill、Redis Session 和旧接口阻断。

如果网关无法在镜像回滚前可靠阻断旧路径，则该镜像回滚不安全，应停止。

## 6. 发布验收证据

进入 `main` 前至少保留以下可观察证据：

- 精确 feature SHA、`big-main` SHA 和 OCI
  `org.opencontainers.image.revision`。
- PostgreSQL 16 migration、事务回滚、冲突和并发测试结果。
- 目标 Redis 拓扑上的 principal index、全部删除、失败重试和最终清空结果。
- 次账号旧 Web Session 与 API Token 均返回 401，主账号不受影响。
- Browser Provider callback replay、proof/intent 过期和 preview stale 结果。
- 日志、响应、URL、审计和指标不含密码、raw proof、Session ID/nonce、OAuth token、
  CAS ticket 或高基数用户标识。
- 隔离测试资源已精确清理，既有服务测试前后健康且未重启宿主机。

缺少任一证据时保持功能关闭，不以管理员手工改库或“页面能打开”替代。
