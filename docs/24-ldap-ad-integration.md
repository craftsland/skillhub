# LDAP/Active Directory 接入指南

本文说明如何把 OpenLDAP 或 Active Directory 作为 Credential Provider 接入 SkillHub
统一身份核心。LDAP 默认关闭；配置不完整、Authority 冲突或协议定义无效时不会出现在
登录方法目录中，也不会初始化连接池。

## 1. 安全模型

LDAP Adapter 只负责在目录中验证凭据并返回外部身份事实：

```text
service bind/search → 唯一结果 → user DN bind → 稳定 Subject/属性
  → ProviderAuthenticationResult → 统一身份核心 → 平台账号与 Session
```

Adapter 不创建或选择平台账号，不通过 email、username、DN 或 display name 静默绑定账号。
首次登录、重复登录、显式 Identity Link、Account Merge、资料同步和准入策略均由统一身份
核心处理。

生产环境必须使用以下一种传输：

- `ldaps://`；
- `ldap://` 并启用 StartTLS。

客户端使用 JVM 默认 TrustStore 和 hostname verification，不提供生产 trust-all 开关。
使用企业私有 CA 时，应把 CA 证书加入 SkillHub Server 镜像的 JVM TrustStore。不要把
bind password、用户密码或 TrustStore password 写入 ConfigMap、镜像层、日志或 Git。

## 2. 身份键

| 目录类型 | 默认 Subject attribute | 默认 Subject type | 说明 |
|---|---|---|---|
| `OPENLDAP` | `entryUUID` | `ldap_entry_uuid` | 必须是唯一 UUID |
| `ACTIVE_DIRECTORY` | `objectGUID` | `ad_object_guid` | 按 AD 固定 little-endian 字节序转换 |
| `CUSTOM` | 无 | 无 | 两项都必须显式配置 |

`provider-code`、`authority`、`subject-attribute` 和 `subject-type` 共同决定持久身份绑定。
产生 Binding 后，endpoint 和证书可以轮换，但不能把相同 Authority 指向另一套目录，也
不能在普通配置变更中切换 Subject 语义。

不要把 `uid`、`sAMAccountName`、DN、mail 或 display name 当作默认 Subject。它们可能
被管理员修改或复用。

## 3. 配置

| 环境变量 | 必填 | 默认值 | 说明 |
|---|---:|---|---|
| `SKILLHUB_AUTH_LDAP_ENABLED` | 是 | `false` | 显式启用 Provider |
| `SKILLHUB_AUTH_LDAP_PROVIDER_CODE` | 是 | `ldap` | 稳定 Provider Instance code |
| `SKILLHUB_AUTH_LDAP_DISPLAY_NAME` | 是 | `Corporate Directory` | 登录页展示名 |
| `SKILLHUB_AUTH_LDAP_AUTHORITY` | 是 | 空 | 稳定目录身份域 ID，不是 endpoint |
| `SKILLHUB_AUTH_LDAP_URL` | 是 | 空 | `ldaps://host:636` 或 `ldap://host:389` |
| `SKILLHUB_AUTH_LDAP_START_TLS` | 是 | `false` | `ldap://` 在生产必须设为 `true` |
| `SKILLHUB_AUTH_LDAP_DIRECTORY_TYPE` | 是 | `OPENLDAP` | `OPENLDAP`、`ACTIVE_DIRECTORY`、`CUSTOM` |
| `SKILLHUB_AUTH_LDAP_BASE_DN` | 是 | 空 | 目录搜索根 DN |
| `SKILLHUB_AUTH_LDAP_USER_SEARCH_BASE` | 否 | 空 | 相对于 base DN 的用户搜索 DN |
| `SKILLHUB_AUTH_LDAP_USER_SEARCH_FILTER` | 是 | `(uid={0})` | 必须恰好包含一个 `{0}`；用户名会按 LDAP filter 规则 escape |
| `SKILLHUB_AUTH_LDAP_BIND_DN` | 是 | 空 | 只读 service account DN |
| `SKILLHUB_AUTH_LDAP_BIND_PASSWORD` | 是 | 空 | service account 密码，只能来自 Secret |
| `SKILLHUB_AUTH_LDAP_SUBJECT_ATTRIBUTE` | CUSTOM 必填 | 目录默认值 | 稳定、唯一且不可变的属性 |
| `SKILLHUB_AUTH_LDAP_SUBJECT_TYPE` | CUSTOM 必填 | 目录默认值 | 统一身份 Subject type |
| `SKILLHUB_AUTH_LDAP_USERNAME_ATTRIBUTE` | 否 | `uid` | 平台 username 候选属性；可设为空禁用 |
| `SKILLHUB_AUTH_LDAP_DISPLAY_NAME_ATTRIBUTE` | 否 | `displayName` | display name 候选属性 |
| `SKILLHUB_AUTH_LDAP_EMAIL_ATTRIBUTE` | 否 | `mail` | email 候选属性 |
| `SKILLHUB_AUTH_LDAP_AVATAR_URL_ATTRIBUTE` | 否 | 空 | avatar URL 候选属性 |
| `SKILLHUB_AUTH_LDAP_EMAIL_AUTHORITATIVE` | 否 | `false` | 仅在目录确为企业权威 email 源时启用 |
| `SKILLHUB_AUTH_LDAP_CONNECT_TIMEOUT` | 否 | `PT5S` | TCP/TLS 连接超时，最大 1 分钟 |
| `SKILLHUB_AUTH_LDAP_READ_TIMEOUT` | 否 | `PT10S` | LDAP 响应超时，最大 1 分钟 |
| `SKILLHUB_AUTH_LDAP_POOL_WAIT_TIMEOUT` | 否 | `PT2S` | 连接池等待超时，最大 1 分钟 |
| `SKILLHUB_AUTH_LDAP_MAX_CONCURRENT_REQUESTS` | 否 | `16` | 连接池上限，1–256 |
| `SKILLHUB_AUTH_LDAP_MAX_ATTRIBUTE_VALUES` | 否 | `16` | 单个映射属性的值数量上限，1–64 |

要在官方 Web 登录页显示 LDAP 用户名/密码表单，还需要：

```dotenv
SKILLHUB_AUTH_DIRECT_ENABLED=true
SKILLHUB_WEB_AUTH_DIRECT_ENABLED=true
SKILLHUB_WEB_AUTH_DIRECT_PROVIDER=ldap-main
```

LDAP Provider 即使不作为默认 Web Direct Provider，也可以用于显式 Identity Link 和
Account Merge 的 credential verification。

### Docker Compose

复制 `.env.release.example` 为 `.env.release`，填写 LDAP 字段并运行：

```bash
./scripts/validate-release-config.sh .env.release
docker compose --env-file .env.release -f compose.release.yml up -d
```

`.env.release` 已被 Git 忽略。不要把真实 bind password 复制回示例文件或提交记录。

### Helm

```yaml
auth:
  direct:
    enabled: true
    provider: ldap-main
  ldap:
    enabled: true
    providerCode: ldap-main
    displayName: Corporate Directory
    authority: corp-directory
    url: ldaps://ldap.example.com:636
    startTls: false
    directoryType: OPENLDAP
    baseDn: dc=example,dc=com
    userSearchBase: ou=people
    userSearchFilter: "(uid={0})"
    bindDn: cn=skillhub,ou=services,dc=example,dc=com
    subjectAttribute: ""
    subjectType: ""
    usernameAttribute: uid
    displayNameAttribute: displayName
    emailAttribute: mail
    avatarUrlAttribute: ""
    emailAuthoritative: false
    connectTimeout: PT5S
    readTimeout: PT10S
    poolWaitTimeout: PT2S
    maxConcurrentRequests: 16
    maxAttributeValues: 16
secrets:
  ldapBindPassword: <secret-value>
```

生产环境建议设置 `existingSecret`，并在该 Secret 中提供固定 key
`ldap-bind-password`。Chart 在渲染阶段拒绝缺失 bind password、明文 `ldap://`、
LDAPS 与 StartTLS 冲突以及不完整 CUSTOM Subject 映射。

### Kustomize

1. 修改 `deploy/k8s/base/configmap.yaml` 中的 `auth-ldap-*` 字段。
2. 在部署环境的 `skillhub-secret` 中设置 `ldap-bind-password`。
3. 保证 Server Pod 能解析并访问 LDAP endpoint，且 JVM TrustStore 信任目录证书。
4. 应用对应 overlay。

升级旧 Secret 时 LDAP 默认关闭，缺失 `ldap-bind-password` 不会阻止旧部署启动；一旦
启用 LDAP，必须先添加该 key，否则 Provider 会保持隐藏。

## 4. Profile 与 email 策略

普通 LDAP `mail` 固定按 `PROVIDER_ASSERTED` 输入，不满足 verified email 准入，也不会
触发隐式账号绑定。只有管理员确认该目录是企业权威 email 源并设置
`email-authoritative=true` 时，统一身份核心才会在 Provider 的 assurance 上限内提升为
`AUTHORITATIVE`。

display name、email 和 avatar 的覆盖行为继续由统一身份核心的 Provider profile policy
控制。用户名变化不会改变 `entryUUID`/`objectGUID` Binding，也不会创建第二个账号。

## 5. 验证清单

至少验证以下行为：

1. LDAP 关闭或配置不完整时，`/api/v1/auth/methods` 不显示该 Provider，目录没有连接。
2. 正确凭据首次登录创建或进入策略指定的平台账号；重复登录命中同一 userId。
3. 修改 LDAP username 后，使用新 username 登录仍命中相同 `entryUUID`/`objectGUID`。
4. 错误密码与未知账号都向客户端返回通用认证失败，不泄露账号是否存在。
5. 搜索多结果、缺失/多值 Subject、非法 `entryUUID` 和过大属性均 fail closed。
6. 包含 `*`、`(`、`)`、`\\` 和 NUL 的 username 不能改变搜索 filter 语义。
7. LDAPS 和 StartTLS 使用受信证书成功；不可信证书或 hostname 不匹配失败。
8. LDAP 不可用、连接超时、读取超时和连接池耗尽返回稳定安全错误。
9. email collision 返回统一的显式链接要求，不复用或接管已有账号。
10. Identity Link 与 Account Merge 需要 fresh credential verification，成功 intent 不能重放。
11. 日志、审计、指标和异常中不包含用户密码、bind password、完整 LDAP 响应或 filter 输入。

低基数指标名为 `skillhub.auth.ldap`，标签只包含 `provider`、`transport` 和 `result`。

## 6. 升级与回滚

- 新 Provider 和全部配置默认关闭，不修改数据库 schema、Spring Session 序列化或现有
  GitHub/GitLab/OIDC/CAS/本地密码行为。
- 从旧版本升级时，未设置 LDAP 环境变量的部署保持原行为。
- 已产生 LDAP Binding 后回滚旧版本会暂时失去 LDAP 登录入口，但不会删除账号、Binding
  或业务数据；重新升级并恢复相同 provider code、authority 和 Subject 映射后可继续使用。
- endpoint、证书和 service account 可以轮换；Authority 或 Subject 语义变化必须执行
  显式迁移，不能通过覆盖配置完成。
