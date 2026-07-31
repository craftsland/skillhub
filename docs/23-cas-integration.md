# CAS 2.0/3.0 接入指南

本文说明如何把一个 CAS Provider Instance 接入 SkillHub 统一身份核心。CAS 登录默认关闭，
配置不完整或 Authority 状态异常时不会出现在登录方法目录中。

## 1. 前置条件

- SkillHub 的公开入口和 CAS Server 使用 HTTPS。
- Redis 可用。CAS state 使用 Redis 原子消费，以支持多 Pod 和重放保护。
- CAS Server 已允许下面的精确 Service URL：

  ```text
  https://<skillhub-host>/api/v1/auth/cas/<provider-code>/callback
  ```

- 已确认可作为稳定身份键的 CAS principal 或 immutable attribute。

`provider-code` 和 `authority` 是持久身份绑定的一部分。产生 Identity Binding 后不能通过
普通配置变更切换到另一个身份域。

## 2. 配置

| 环境变量 | 必填 | 默认值 | 说明 |
|---|---:|---|---|
| `SKILLHUB_AUTH_CAS_ENABLED` | 是 | `false` | 显式启用 CAS |
| `SKILLHUB_AUTH_CAS_PROVIDER_CODE` | 是 | `cas` | Provider Instance code，需长期稳定 |
| `SKILLHUB_AUTH_CAS_DISPLAY_NAME` | 是 | `CAS` | 登录页展示名 |
| `SKILLHUB_AUTH_CAS_AUTHORITY` | 是 | 空 | 稳定 CAS 身份域 ID |
| `SKILLHUB_AUTH_CAS_SERVER_URL` | 是 | 空 | CAS Server 根地址，例如 `https://cas.example.com/cas` |
| `SKILLHUB_AUTH_CAS_SERVICE_URL` | 是 | 空 | 精确 SkillHub callback，不含 query/fragment |
| `SKILLHUB_AUTH_CAS_PROTOCOL_VERSION` | 是 | `3.0` | `2.0` 或 `3.0` |
| `SKILLHUB_AUTH_CAS_SUBJECT_TYPE` | 是 | `cas_principal` | 统一身份核心中的 Subject type |
| `SKILLHUB_AUTH_CAS_ATTRIBUTES_SUBJECT` | 否 | 空 | 为空时使用 CAS principal；否则使用唯一 immutable attribute |
| `SKILLHUB_AUTH_CAS_ATTRIBUTES_DISPLAY_NAME` | 否 | 空 | display name attribute |
| `SKILLHUB_AUTH_CAS_ATTRIBUTES_EMAIL` | 否 | 空 | email attribute，固定按 asserted 处理 |
| `SKILLHUB_AUTH_CAS_ATTRIBUTES_AVATAR_URL` | 否 | 空 | avatar URL attribute |
| `SKILLHUB_AUTH_CAS_CONNECT_TIMEOUT` | 否 | `PT5S` | 连接超时 |
| `SKILLHUB_AUTH_CAS_READ_TIMEOUT` | 否 | `PT10S` | 请求总超时 |
| `SKILLHUB_AUTH_CAS_STATE_TTL` | 否 | `PT5M` | 登录 state 有效期，最大 15 分钟 |
| `SKILLHUB_AUTH_CAS_MAX_RESPONSE_BYTES` | 否 | `1048576` | validation 响应上限，1 KiB–1 MiB |

CAS 返回的普通 email attribute 不是 verified email，不能用于
`EMAIL_DOMAIN` 准入或静默账号绑定。

### Docker Compose

编辑 `.env.release`：

```dotenv
SKILLHUB_AUTH_CAS_ENABLED=true
SKILLHUB_AUTH_CAS_PROVIDER_CODE=cas-main
SKILLHUB_AUTH_CAS_DISPLAY_NAME=Corporate CAS
SKILLHUB_AUTH_CAS_AUTHORITY=corp-cas
SKILLHUB_AUTH_CAS_SERVER_URL=https://cas.example.com/cas
SKILLHUB_AUTH_CAS_SERVICE_URL=https://skills.example.com/api/v1/auth/cas/cas-main/callback
SKILLHUB_AUTH_CAS_PROTOCOL_VERSION=3.0
SKILLHUB_AUTH_CAS_SUBJECT_TYPE=cas_principal
SKILLHUB_AUTH_CAS_ATTRIBUTES_DISPLAY_NAME=displayName
SKILLHUB_AUTH_CAS_ATTRIBUTES_EMAIL=mail
```

启动前运行：

```bash
./scripts/validate-release-config.sh .env.release
```

### Helm

```yaml
auth:
  cas:
    enabled: true
    providerCode: cas-main
    displayName: Corporate CAS
    authority: corp-cas
    serverUrl: https://cas.example.com/cas
    serviceUrl: https://skills.example.com/api/v1/auth/cas/cas-main/callback
    protocolVersion: "3.0"
    subjectType: cas_principal
    connectTimeout: PT5S
    readTimeout: PT10S
    stateTtl: PT5M
    maxResponseBytes: 1048576
    attributes:
      subject: ""
      displayName: displayName
      email: mail
      avatarUrl: ""
```

Chart 在渲染阶段拒绝 HTTP endpoint、缺失 URL 和 provider code 不匹配的 callback。

### Kustomize

修改 `deploy/k8s/base/configmap.yaml` 中的 `auth-cas-*` 字段，然后重新应用 overlay。
CAS 配置不包含 client secret；若企业扩展引入凭证，必须放入 Kubernetes Secret，不能放
在 ConfigMap。

## 3. 身份映射

默认映射：

```text
primary subject = CAS principal
subject type    = cas_principal
email assurance = PROVIDER_ASSERTED
aliases         = none
```

如果 CAS principal 可能随用户名变更，必须配置
`SKILLHUB_AUTH_CAS_ATTRIBUTES_SUBJECT` 指向 CAS Server 明确定义且实际返回的 immutable
attribute，并为该属性选择稳定的 `subject-type`。属性缺失、多值或空值时登录 fail closed。

不要把 email、display name 或临时用户名当作稳定 Subject。

## 4. 验证

1. 匿名请求登录方法目录：

   ```bash
   curl -fsS 'https://skills.example.com/api/v1/auth/methods'
   ```

   只在 Provider 为 `READY` 时应出现 `CAS_REDIRECT`。

2. 在浏览器点击 CAS 登录，确认重定向到 CAS `/login`，其 `service` 解码后与配置的
   callback 加一次性 `state` 完全一致。
3. 完成 CAS 登录，确认返回原始 `returnTo` 或默认页面，并能请求
   `/api/v1/auth/me`。
4. 再次请求相同 callback，必须得到 `casInvalidState` 或 CAS Ticket 验证失败，不能建立
   第二个 Session。
5. 检查应用日志中不包含 `ST-` Ticket、validation URL、上游完整响应或用户属性。
6. 禁用 Provider 后，方法目录不再显示 CAS，且点击旧 URL 不应连接 CAS Server。

建议分别验证 CAS 2 XML、CAS 3 JSON、CAS 3 XML fallback、无效 Ticket、错误 Service、
超时、TLS 失败、XXE、超大响应和 Redis 不可用。

## 5. 升级与回滚

- 新配置默认关闭，不影响现有本地密码、GitHub、GitLab 或 OIDC 登录。
- 本次接入不修改 `PlatformPrincipal` 或现有 Session 序列化结构。
- 旧版本回滚后会忽略 CAS 环境变量；现有非 CAS 登录仍可使用。
- CAS 已产生 Binding 后回滚会暂时失去 CAS 登录入口，但不会删除账号、Binding 或业务
  数据。
- 修改 CAS endpoint 可以保持同一 Authority；修改 Authority 必须走统一身份设计中的
  显式 Authority 迁移流程。

## 6. 安全实现说明

实现阶段验证了 Spring Security CAS 所依赖的 Apereo Java CAS Client。其 4.1.1
`AbstractUrlBasedTicketValidator` 仍会在 DEBUG 记录包含 Ticket 的 validation URL 和完整
响应；CAS 2 自定义属性解析路径也没有满足本项目要求的全部 XML parser fail-closed
设置。因此当前实现没有调用该库的 URL validator，而是使用受限 JDK HTTP transport 和
严格 parser：

- 禁止 redirect；
- 明确连接、请求和响应大小上限；
- XML 禁止 DOCTYPE、外部实体、外部 DTD 和外部 schema；
- Ticket、完整响应和属性不写日志或异常；
- CAS 3 优先 JSON，并支持受限 XML fallback。

上游参考：

- [Spring Security CAS reference](https://docs.spring.io/spring-security/reference/servlet/authentication/cas.html)
- [Apereo validator logging](https://github.com/apereo/java-cas-client/blob/cas-client-4.1.1/cas-client-core/src/main/java/org/apereo/cas/client/validation/AbstractUrlBasedTicketValidator.java)
- [Apereo CAS 2 attribute parser](https://github.com/apereo/java-cas-client/blob/cas-client-4.1.1/cas-client-core/src/main/java/org/apereo/cas/client/validation/Cas20ServiceTicketValidator.java)

如果上游版本修复这些问题，可以在保持错误分类、响应上限和无敏感日志测试的前提下重新
评估替换 transport/parser。
