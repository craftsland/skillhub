# 认证扩展与私有 SSO 兼容设计

> 本文描述 Provider Registry 落地后的当前扩展边界。完整身份、不变量、迁移顺序和协议
> 路线以 [统一身份联邦设计](./21-unified-identity-federation-design.md) 为准。

## 1. 目标

SkillHub 保留已有公共登录协议，同时允许受信、随发布物构建的企业认证 Adapter 接入。
Adapter 只验证协议并返回外部身份事实；Provider Registry 和统一身份核心负责 Provider
路由、Authority 锁定、账号创建、身份绑定、审批、资料同步、角色保护和 Session。

不支持上传或热加载第三方 JAR。Adapter 与 SkillHub 运行在同一 JVM，必须经过代码
Review 和 Provider Conformance Kit。

## 2. 不可绕过的边界

- Adapter 不返回或构造 `PlatformPrincipal`。
- Adapter 不创建、查询或修改 `UserAccount`、平台角色、Namespace role 或 Binding。
- Adapter 不操作 `HttpSession`、`SecurityContext` 或 Redis。
- Adapter 不把 provider code、Authority、平台 userId 或角色放入认证结果。
- Adapter 不把 token、密码、Cookie、Ticket、Authorization header 或原始上游响应放入
  `ProviderAuthenticationResult`。
- Adapter 的 `provider()` 定义必须来自受信代码和服务端配置，不能来自登录请求或上游
  响应。
- Provider 未启用、配置冲突、Authority 不匹配或状态非 `READY` 时，Registry 不返回
  路由；Adapter 的网络认证方法不会被调用。

外部 I/O 顺序固定为：

```text
Provider Registry READY gate
  → Adapter 验证协议或凭证（事务外）
  → ProviderAuthenticationResult
  → ExternalIdentityLoginService（事务内）
  → PlatformPrincipal
  → PlatformSessionService
```

## 3. 公共协议兼容

以下 HTTP API 保持不变：

- `GET /api/v1/auth/providers`
- `GET /api/v1/auth/methods`
- `POST /api/v1/auth/direct/login`
- `POST /api/v1/auth/session/bootstrap`
- `POST /api/v1/auth/local/login`

兼容入口仍默认关闭：

```yaml
skillhub:
  auth:
    direct:
      enabled: false
    session-bootstrap:
      enabled: false
```

关闭时返回 `403`；入口开启但 provider 不存在或不具备对应能力时返回 `400`；被动请求中
没有有效外部身份时返回 `401`。Provider Authority 不匹配等运行故障返回 `503`。

`provider=local` 的 direct-login 兼容行为保留，但本地密码不属于外部 Provider，也不进入
Identity Binding。新的企业认证必须实现下面的 Adapter 契约。

## 4. Provider Instance 定义

Credential 和 Passive Adapter 都声明一个不可变的
`ProviderInstanceDefinition`：

```java
new ProviderInstanceDefinition(
    "private-sso",
    "private-sso",
    "https://sso.example",
    "Enterprise SSO",
    "private_subject",
    "private_subject",
    Map.of("private_subject", SubjectNormalization.EXACT),
    List.of("display_name"),
    List.of("email"),
    List.of("avatar_url"),
    EmailAssurance.VERIFIED,
    true
);
```

字段含义：

- `providerCode`：稳定 Provider Instance 标识；不能因部署或登录方式变化。
- `protocol`：写入认证证据和 Authority fingerprint 的协议代码。
- `canonicalAuthority`：该 Provider 所代表的身份域。
- `primarySubjectType`：稳定外部主键的类型。
- `subjectNormalizations`：核心允许的 Subject 类型和规范化规则。
- 属性列表：统一核心可读取的 display name、email、avatar 候选键及优先级。
- `emailAssuranceLimit`：该受信 Adapter 允许的 email assurance 上限。
- `enabled`：Adapter 能力开关；关闭时不进入目录和路由。

同一 Provider 同时实现 Credential 和 Passive 能力时，两者返回的定义必须完全一致。
Registry 检测到定义或同类能力冲突时，对整个 Provider fail closed。

## 5. Adapter 契约

### 5.1 Browser

Browser 协议保留各自强类型 exchange：

```java
public interface BrowserAuthenticationAdapter<T> {
    ProviderAuthenticationResult authenticate(T exchange);
}
```

Redirect、Callback、state、nonce、SAML POST 或 CAS Ticket 的传输流程仍由协议模块持有，
不使用万能请求对象。现有 GitHub/GitLab claims Adapter 已使用此结果契约；OAuth 路由由
Registry 对服务端 `ClientRegistration` 做身份匹配。

### 5.2 Credential

```java
public interface CredentialAuthenticationAdapter {
    ProviderInstanceDefinition provider();
    ProviderAuthenticationResult authenticate(
        CredentialAuthenticationRequest request
    );
}
```

适用于 LDAP bind、企业 RPC 等主动凭证校验。全局入口由
`skillhub.auth.direct.enabled` 控制。

### 5.3 Passive

```java
public interface PassiveAuthenticationAdapter {
    ProviderInstanceDefinition provider();
    Optional<ProviderAuthenticationResult> authenticate(
        HttpServletRequest request
    );
}
```

适用于可信 Header、签名 JWT、已有企业会话和 SPNEGO。Adapter 可以只读请求，但不能写
Session 或 Security Context。全局入口由
`skillhub.auth.session-bootstrap.enabled` 控制。

旧名称 `DirectAuthProvider` 和 `PassiveSessionAuthenticator` 仅保留为待删除的源码迁移
别名；它们已经继承新契约，不能再返回 `PlatformPrincipal`。

### 5.4 失败分类

Adapter 不能抛出携带上游响应、用户名或凭证的自由文本异常。协议校验或上游调用失败时，
统一抛出 `ProviderAuthenticationException`，只携带
`ProviderAuthenticationFailureCode`：

- `UPSTREAM_INVALID_CREDENTIALS`、`REPLAY_DETECTED` → 401。
- `UPSTREAM_ACCESS_DENIED` → 403。
- `UPSTREAM_UNAVAILABLE`、`UPSTREAM_MISCONFIGURED`、
  `TLS_VALIDATION_FAILED`、`UPSTREAM_INVALID_RESPONSE` → 503。

`PassiveAuthenticationAdapter` 只有在请求完全没有外部认证信息时返回 `Optional.empty()`；
断言存在但无效、过期、重放或无法验证时必须使用稳定失败码，不能伪装成“未登录”。

## 6. Auth Method Catalog

`GET /api/v1/auth/methods` 只从 Registry 的 `READY` Provider 和已协商能力投影：

```text
Browser    → OAUTH_REDIRECT
Credential → DIRECT_PASSWORD
Passive    → SESSION_BOOTSTRAP
```

返回的 action URL 由核心按能力生成。Adapter 不能提供任意 URL，也不能向目录暴露
Authority、endpoint、属性映射或上游错误。

`GET /api/v1/auth/providers` 继续只返回 Browser/OAuth 兼容目录，保持旧前端兼容。

## 7. 从旧 SPI 迁移

旧实现如果执行了以下操作，必须删除：

- 按外部 UID 自行查询或创建平台用户。
- 自行创建 Identity Binding。
- 从 email、username 或 Provider login 推导平台 userId。
- 构造 `PlatformPrincipal` 或授予角色。
- 在 Adapter 中建立 Session。

迁移步骤：

1. 把稳定 provider code、protocol、Authority、Subject 类型和属性映射写入
   `ProviderInstanceDefinition`。
2. 把外部 UID 转成 `SubjectCandidate`。
3. 把非敏感资料转成带 `ProviderAttributeTrust` 的属性。
4. 返回协议一致的 `ProtocolAuthenticationEvidence`。
5. 让统一身份核心按 `AUTO`、`APPROVAL` 或 `EXISTING_BINDING_ONLY` 完成账号和 Binding。
6. 为 Adapter 增加 Conformance、稳定失败码、超时和无敏感日志测试。

具体实现示例见
[私有 SSO 接入手册](./12-private-sso-integration-playbook.md)。

## 8. 前端与部署

前端运行时配置保持不变：

- `SKILLHUB_WEB_AUTH_DIRECT_ENABLED`
- `SKILLHUB_WEB_AUTH_DIRECT_PROVIDER`
- `SKILLHUB_WEB_AUTH_SESSION_BOOTSTRAP_ENABLED`
- `SKILLHUB_WEB_AUTH_SESSION_BOOTSTRAP_PROVIDER`
- `SKILLHUB_WEB_AUTH_SESSION_BOOTSTRAP_AUTO`

后端开关、Provider definition 的 `enabled` 和前端开关需要同时满足。建议先启用
Credential，再人工验证 Passive Cookie/Header 的作用域、SameSite、Secure、CSRF 和代理
信任边界，最后才评估自动 bootstrap。
