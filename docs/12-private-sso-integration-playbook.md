# 私有 SSO 接入手册

本文给出 Provider Registry 架构下的私有 SSO 实施步骤。开始前先阅读：

- [认证扩展与私有 SSO 兼容设计](./11-auth-extensibility-and-private-sso.md)
- [统一身份联邦设计](./21-unified-identity-federation-design.md)

## 1. 先决定交互能力

根据真实上游能力选择 Adapter，不要实现万能 Provider：

| 上游能力 | SkillHub Adapter |
|---|---|
| 浏览器 Redirect/Callback | `BrowserAuthenticationAdapter<T>` |
| 用户名密码、LDAP bind、企业 RPC | `CredentialAuthenticationAdapter` |
| 可信 Cookie/Header/JWT、已有企业会话 | `PassiveAuthenticationAdapter` |

一个 Provider Instance 可以同时具备 Credential 和 Passive 能力。两种能力必须使用同一个
provider code、Authority、Subject 语义和 `ProviderInstanceDefinition`。

## 2. 固定 Provider Instance

先确定稳定值：

```text
providerCode: private-sso
protocol: private-sso
canonicalAuthority: https://sso.example
primarySubjectType: private_subject
```

选择原则：

- `providerCode` 标识一个身份域，不标识某个登录按钮。
- `canonicalAuthority` 必须能区分不同租户、目录或 SSO 集群。
- Subject 必须来自不可变外部主键，例如 UID、entryUUID 或 OIDC `sub`。
- username、display name 和 email 都不能作为默认 Subject。
- 已产生 Binding 后不能静默改变 protocol、Authority 或 Subject 规范化。

建议由一个配置组件构造并复用定义：

```java
@ConfigurationProperties("private-sso")
public class PrivateSsoProperties {
    private boolean enabled;
    private URI authority;
    private Duration connectTimeout;
    private Duration readTimeout;
    // getters/setters
}

@Component
public class PrivateSsoProviderDefinition {
    private final PrivateSsoProperties properties;

    public ProviderInstanceDefinition get() {
        return new ProviderInstanceDefinition(
            "private-sso",
            "private-sso",
            properties.getAuthority().toString(),
            "Enterprise SSO",
            "private_subject",
            "private_subject",
            Map.of("private_subject", SubjectNormalization.EXACT),
            List.of("display_name"),
            List.of("email"),
            List.of("avatar_url"),
            EmailAssurance.VERIFIED,
            properties.isEnabled()
        );
    }
}
```

`provider()` 只读取已经绑定和校验的服务端配置，不连接上游。缺少 Authority、超时或
凭证配置时，应让 Adapter 不注册、返回 disabled definition，或在启动校验中明确失败；
不能先进入登录目录，再在用户提交凭证后发现配置缺失。

## 3. 封装上游客户端

协议 I/O 与结果映射分开：

```java
public interface PrivateSsoClient {
    PrivateSsoUser verifyPassword(String username, String password);
    Optional<PrivateSsoUser> verifySession(HttpServletRequest request);
}

public record PrivateSsoUser(
    String stableUid,
    String displayName,
    String email,
    boolean emailVerified,
    URI avatarUrl,
    Instant authenticatedAt
) {}
```

客户端要求：

- 明确 connect/read timeout；不得无限等待。
- HTTPS 校验证书和主机名；不能提供“跳过 TLS 校验”开关。
- 不记录密码、Cookie、Ticket、Authorization header、token 或完整上游响应。
- 401/403、5xx、timeout、TLS 和响应格式错误转换为
  `ProviderAuthenticationException` 的稳定失败码；异常 message 和 cause 不进入用户响应
  或普通业务日志。
- 不在数据库事务中执行网络 I/O。
- 上游返回的 provider code、Authority、角色和平台 userId 一律忽略。

## 4. 映射统一认证结果

把上游用户映射为纯协议事实：

```java
final class PrivateSsoResultMapper {

    ProviderAuthenticationResult map(PrivateSsoUser user) {
        Map<String, List<ProviderAttributeValue>> attributes =
            new LinkedHashMap<>();
        put(attributes, "display_name", user.displayName(),
            ProviderAttributeTrust.ASSERTED);
        put(attributes, "email", user.email(),
            user.emailVerified()
                ? ProviderAttributeTrust.VERIFIED
                : ProviderAttributeTrust.UNVERIFIED);
        put(attributes, "avatar_url",
            user.avatarUrl() == null ? null : user.avatarUrl().toString(),
            ProviderAttributeTrust.ASSERTED);

        return new ProviderAuthenticationResult(
            new SubjectCandidate(
                "private_subject",
                user.stableUid()
            ),
            List.of(),
            attributes,
            new ProtocolAuthenticationEvidence(
                "private-sso",
                user.authenticatedAt(),
                Set.of("password")
            )
        );
    }
}
```

结果中不能加入 token、密码、Cookie、Ticket、Authorization header、原始 JSON/XML、
platform userId 或角色。统一核心会再次校验 protocol、Subject allowlist、载荷大小和
email assurance 上限。

## 5. 实现 Credential Adapter

```java
@Component
public class PrivateSsoCredentialAdapter
        implements CredentialAuthenticationAdapter {

    private final PrivateSsoProviderDefinition definition;
    private final PrivateSsoClient client;
    private final PrivateSsoResultMapper mapper;

    @Override
    public ProviderInstanceDefinition provider() {
        return definition.get();
    }

    @Override
    public ProviderAuthenticationResult authenticate(
            CredentialAuthenticationRequest request) {
        PrivateSsoUser user = client.verifyPassword(
            request.username(),
            request.password()
        );
        return mapper.map(user);
    }
}
```

Adapter 不查询或创建 SkillHub 用户，不建立 Binding，不决定审批状态，也不建立 Session。

## 6. 实现 Passive Adapter

```java
@Component
public class PrivateSsoPassiveAdapter
        implements PassiveAuthenticationAdapter {

    private final PrivateSsoProviderDefinition definition;
    private final PrivateSsoClient client;
    private final PrivateSsoResultMapper mapper;

    @Override
    public ProviderInstanceDefinition provider() {
        return definition.get();
    }

    @Override
    public Optional<ProviderAuthenticationResult> authenticate(
            HttpServletRequest request) {
        return client.verifySession(request).map(mapper::map);
    }
}
```

Passive Adapter 可以只读当前请求。不要重定向、写 Cookie、写 Session 或修改
`SecurityContext`。无有效外部会话时返回 `Optional.empty()`。

## 7. 配置 Provisioning 和资料同步

统一身份核心按 Provider 配置处理首次登录：

```yaml
skillhub:
  auth:
    identity:
      providers:
        private-sso:
          provisioning-mode: APPROVAL
          profile-sync:
            display-name: INITIAL_ONLY
            email: FILL_IF_EMPTY
            avatar-url: PRESERVE_LOCAL
```

模式：

- `AUTO`：首次登录自动创建账号和 Binding。
- `APPROVAL`：创建 PENDING 账号，管理员批准后才可登录。
- `EXISTING_BINDING_ONLY`：只允许预先建立的 Binding。

不要在 Adapter 中实现上述分支。email 碰撞只会得到 `LINK_REQUIRED`，不会自动绑定或
合并账号。

## 8. 开启兼容入口

后端：

```yaml
skillhub:
  auth:
    direct:
      enabled: true
    session-bootstrap:
      enabled: true
```

前端：

```text
SKILLHUB_WEB_AUTH_DIRECT_ENABLED=true
SKILLHUB_WEB_AUTH_DIRECT_PROVIDER=private-sso
SKILLHUB_WEB_AUTH_SESSION_BOOTSTRAP_ENABLED=true
SKILLHUB_WEB_AUTH_SESSION_BOOTSTRAP_PROVIDER=private-sso
```

建议先只开启 Credential。Passive 需要确认代理信任、Cookie domain/path、SameSite、
Secure 和 CSRF 后再开启；自动 bootstrap 最后评估。

## 9. Provider Conformance

Adapter 测试应复用 `ProviderConformanceKit`，并补充协议专属 fixture：

- definition 连续读取稳定且与预期 provider code/Authority 一致。
- Subject 稳定、非空、类型在 allowlist。
- evidence protocol 与 definition 一致。
- email attribute 的 trust 不超过 definition 的 `emailAssuranceLimit`。
- 认证结果不含 secret-bearing attribute。
- 401/403、5xx、timeout、TLS、响应格式错误使用
  `ProviderAuthenticationFailureCode` 分类正确。
- disabled/misconfigured 时 Registry 不返回路由，认证方法零调用。
- 日志不含用户名密码、token、Cookie、Ticket 或完整响应。
- Adapter class 不依赖账号、Binding、角色、Session 或 JPA Repository。
- Credential 与 Passive 使用同一 Provider 时 definition 完全一致。

至少准备以下测试：

```text
valid credential
invalid credential
upstream timeout
TLS failure
malformed response
disabled provider
misconfigured provider
stable subject fixture
verified/unverified email
repeated login reuses binding
APPROVAL and EXISTING_BINDING_ONLY
```

并发首次登录、唯一约束和 Authority pin 必须在 PostgreSQL 上验证，不能只依赖 H2。

## 10. 部署验收

按 Expand → Contract → Profile/Provisioning → Provider Registry 的顺序部署。测试环境
验收至少包括：

1. 从旧版本升级，Flyway 成功且旧 OAuth/Binding 可继续登录。
2. `/api/v1/auth/providers` 旧响应兼容。
3. `/api/v1/auth/methods` 只展示 `READY` 且全局开关启用的能力。
4. disabled/misconfigured/Authority mismatch Provider 不展示且不连接上游。
5. Credential 和 Passive 成功后进入相同 Identity Binding 和 Session 链路。
6. PENDING、DISABLED、MERGED、system account 均按核心策略 fail closed。
7. 多 Pod + Redis Session 下刷新和切换实例仍保持登录态。
8. 回滚到兼容版本时旧 Binding 和本地登录不受损。

通过后再决定是否合入 `main`；不要在未验证的情况下直接修改生产 Provider 配置。
