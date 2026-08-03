# 企业身份 Broker 接入指南

本文定义 SkillHub 接入企业 LDAP/AD、SAML、Kerberos 等身份源时的推荐边界：由
Keycloak、authentik 或 Dex 等成熟身份 Broker 负责上游协议，Broker 对 SkillHub 暴露一个
标准 OIDC Provider。SkillHub 只实现 OIDC Authorization Code 登录，并把结果交给统一身份
核心处理。

这不是把 LDAP、SAML 或 Kerberos 的协议细节塞进 SkillHub，也不是给 Broker 返回的 email
做隐式账号绑定。开始前先阅读：

- [统一身份联邦设计](./21-unified-identity-federation-design.md)
- [OIDC 登录配置](./09-deployment.md#8-oidc-登录配置)
- [私有 SSO 接入手册](./12-private-sso-integration-playbook.md)

## 1. 什么时候使用 Broker

| 企业能力 | 推荐接入 | SkillHub 原生实现 | 说明 |
| --- | --- | --- | --- |
| LDAP/AD 用户密码 | Broker 的 LDAP/AD Source → OIDC | LDAP Adapter | 已有 LDAP 目录、希望统一审计和 MFA 时优先 Broker |
| SAML 2.0 | SAML IdP → Broker → OIDC | 暂不原生支持 | 先使用 Broker；不会在本指南中引入 XML 解析器 |
| Kerberos/SPNEGO | Broker/反向代理 → OIDC | 暂不原生支持 | Kerberos 只负责企业网络内的上游会话 |
| 多个目录或多个 IdP | Broker 统一入口 → OIDC | OIDC Client | SkillHub 为每个稳定身份域保留独立 registration id |

Broker 适合在以下情况下使用：需要 MFA、SAML、Kerberos、LDAP group 同步或企业已有
身份治理平台；希望 SkillHub 只维护一套 OIDC 安全边界；或暂时没有能力承担新的原生
协议的长期兼容责任。

不要因为使用 Broker 就跳过 SkillHub 的 Provider Registry、Authority Lock、email
assurance、Identity Link 和 provisioning policy。Broker 是协议边界，不是账号信任边界。

## 2. 责任边界和请求流

```text
浏览器
  │  GET /oauth2/authorization/corp-sso
  ▼
SkillHub（OIDC client + unified identity core）
  │  Authorization Code（由 Spring Security 管理）
  ▼
Identity Broker（Keycloak / authentik / Dex）
  │  LDAP/AD、SAML、Kerberos、MFA 等上游协议
  └──────────────► 回调 /login/oauth2/code/corp-sso
                         │ code 在后端交换，不进入前端
                         ▼
                  OIDC discovery / token / userinfo
                         │
                         ▼
                  Subject + claims → Binding/Policy/Session
```

SkillHub 的责任：

1. 只信任服务端配置的 `issuer-uri`、OIDC discovery、JWKS、`iss`、`aud` 和 `sub`。
2. 验证 OIDC 结果后，调用统一身份核心；核心决定 Authority、Binding、账号状态、审批、
   资料同步和 Session。
3. 记录低基数认证结果和审计事件；不记录 token、Cookie、authorization code、完整 claims
   或 Broker 响应。

Broker 的责任：

1. 验证 LDAP/AD、SAML、Kerberos 和 MFA，并维护上游会话。
2. 为 SkillHub 注册一个独立 OIDC client，正确设置 redirect URI 和 token 策略；若要强制
   PKCE，必须先验证当前 SkillHub 授权请求确实发送了 `code_challenge`。
3. 只发布经过审核的 OIDC claims；上游 group/role 不会自动变成 SkillHub 的平台角色。

请求流中，浏览器只能看到授权跳转和最终 SkillHub Session Cookie。authorization code、
access token 和 ID token 必须停留在后端通信或受信 SDK 内。

## 3. SkillHub OIDC 配置契约

下面的变量来自现有 Spring Security OAuth2 Client 配置。`CORP` 是示例 registration id；
投入使用后不能随意更换。Compose 发布模板不会自动透传任意 OIDC 变量，请通过 compose
override、Kubernetes Secret/ConfigMap 或部署平台的等价机制注入。

```bash
# non-secret configuration
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CORP_CLIENT_ID=replace-me
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CORP_PROVIDER=corp
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CORP_AUTHORIZATION_GRANT_TYPE=authorization_code
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CORP_REDIRECT_URI={baseUrl}/login/oauth2/code/{registrationId}
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CORP_SCOPE=openid,profile,email
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CORP_CLIENT_NAME=Corporate SSO
SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_CORP_ISSUER_URI=https://sso.example.invalid/realms/skillhub

# secret: inject from a secret store, never commit or place in a public ConfigMap
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CORP_CLIENT_SECRET=replace-me
```

字段规则：

- `registration id`（此处为 `corp`/`CORP`）是平台 Binding 的 provider code，必须稳定且
  与其他身份域唯一。不要用通用的 `oidc` 表示多个不同 Broker。
- `issuer-uri` 是该 Broker 的稳定 OIDC authority，应使用 HTTPS、无 query/fragment，并与
  discovery 文档中的 `issuer` 完全一致。切换 realm、tenant 或 issuer 会触发 Authority
  不匹配保护，而不是静默迁移已有 Binding。
- `redirect-uri` 必须是公开 HTTPS 地址下的精确回调：
  `https://<skillhub-host>/login/oauth2/code/<registration-id>`。不要把通配符、HTTP 公网
  回调或前端地址注册到 Broker。
- `scope` 至少包含 `openid`；`profile,email` 只有在 Broker 确实发布对应 claims 时才添加。
- `client-secret` 只能来自 Secret。优先使用后端 confidential client。当前仓库的 OAuth
  registration 示例和授权请求 resolver 没有单独声明“强制 PKCE”能力；Broker 若强制 PKCE，
  必须先用实际版本验证请求确实包含 `code_challenge`，否则不要把“启用 PKCE”写成已支持的
  配置项。PKCE 支持应作为独立实现和验收项推进。

SkillHub 当前的静态受信 descriptor 对自定义 OIDC registration 的判断是：registration
必须有可解析的 `issuer-uri`，且不能同时被某个专用 OAuth extractor 处理。不能只填 client
id/secret 而省略 issuer，也不能把一个 GitHub/GitLab/DingTalk registration 改造成 Broker
registration。

## 4. Claims 和统一身份规则

### 4.1 必须声明的 claims

| OIDC claim | SkillHub 用途 | 规则 |
| --- | --- | --- |
| `iss` | Authority 校验 | 必须等于服务端配置的 issuer；不能由浏览器或用户输入覆盖 |
| `sub` | typed stable Subject | 只使用 OIDC `sub`；不能用 username、email、DN 或 display name |
| `aud` | client 受众校验 | 必须包含 SkillHub client id；多受众时按 OIDC 规则处理 `azp` |
| `nonce`/`state` | 登录请求绑定 | 由 Spring Security 生成和校验；不要自行拼接或回显 |
| `email` | 资料候选 | 只在 `email_verified=true` 时进入 verified assurance；否则不能覆盖可信邮箱 |
| `name`/`preferred_username` | 展示候选 | 不能作为身份 key；用户已存在时按 Profile Sync policy 处理 |
| `picture` | avatar 候选 | 按 provider policy 处理；不因该字段创建账号 |

OIDC Provider 若没有 `email_verified`，SkillHub 只能把 email 当作 provider-asserted 候选，
不能把它提升为 verified，也不能通过相同 email 自动绑定现有账号。email collision 必须
返回统一的 `LINK_REQUIRED`，由显式 Identity Link 流程处理。

### 4.2 Broker 的 group/role 映射

不要把 `groups`、`roles`、`realm_access` 或任意自定义 claim 直接映射为
`SUPER_ADMIN`、`SKILL_ADMIN` 或 Namespace `OWNER`。若企业需要权限同步，应单独设计
External Entitlement Mapping：

1. Broker 只发布经过审核的 group/claim；
2. SkillHub 管理员配置 allowlist 和目标 namespace；
3. 映射过程可审计、可撤销，默认不授予平台超级管理员；
4. 本 PR 不实现权限映射，未配置时这些 claims 被忽略。

### 4.3 多租户与 Authority Lock

每个 realm、tenant、目录集群或 Dex issuer 都使用独立 registration id。不要让一个
registration 根据请求参数切换 issuer。首次产生 Binding 后，provider code、protocol、
authority、subject type 和 canonicalization 规则必须保持不变；配置漂移应隐藏 Provider
或返回稳定的 `AUTHORITY_MISMATCH`，而不是指向另一个 Broker。

## 5. 三种 Broker 的接入方式

以下只描述边界和需要复制到 SkillHub 的值；Broker 的具体 UI、配置键和版本随产品变化，
以其官方文档为准，不把示例中的占位值直接用于生产。

### 5.1 Keycloak

1. 在目标 realm 配置 LDAP/AD User Federation、SAML Identity Provider 或 Kerberos；
   先在 Keycloak 内验证用户能完成上游登录。
2. 创建 OIDC confidential client，允许 Authorization Code，登记精确的 SkillHub 回调
   URI，并按 Keycloak 文档设置有效的 Web Origins 和 Session/Token 生命周期。若要在
   Keycloak 中强制 PKCE，先按上一节的实际请求验证门禁确认兼容性。
3. 确认 realm 的 discovery `issuer`、JWKS、authorization、token、userinfo 端点属于同一
   HTTPS authority。
4. 将 client id、secret、realm issuer 填入上面的 SkillHub registration；把 `sub` 保持为
   Keycloak 对该用户稳定的 subject，不用可变 username。

### 5.2 authentik

1. 创建 LDAP Source（或其他上游 Source），确认 Source 输出的用户属性和 MFA 策略。
2. 创建 OAuth2/OIDC Provider 与 Application，复制 provider 页面显示的 client id、secret、
   issuer/discovery URL，登记 SkillHub 回调 URI。
3. 在 authentik 中限制该 Provider 的 redirect URI、授权范围和 token audience；不要把内部
   管理 API 或上游 access token 交给 SkillHub。
4. 将 issuer 作为 SkillHub 的 authority，验证 ID token 的 `iss`、`aud`、`sub`、
   `email_verified`，再决定是否启用 email 资料同步。

### 5.3 Dex

1. 在 Dex 配置 LDAP、SAML 或 OIDC connector，并为 SkillHub 创建一个静态 OIDC client。
2. client 的 redirect URI 只登记 `https://<skillhub-host>/login/oauth2/code/<id>`；Dex 的
   `issuer` 使用稳定的外部 HTTPS 地址，不能在不同环境复用同一 issuer。
3. 通过 Dex discovery 确认 `issuer`、JWKS 和端点一致；不要把 connector 的上游 token 或
   LDAP bind password 配置到 SkillHub。
4. 在 SkillHub 中保留 `sub` 原样作为 typed subject；如 connector 变更导致 sub 语义变化，
   先建立迁移方案，不直接覆盖旧 Binding。

## 6. 安全和运维门禁

- Broker、SkillHub 和反向代理之间全部使用证书校验的 HTTPS；不使用 trust-all、跳过主机名
  校验或公网明文 LDAP。
- 代理必须覆盖而不是追加 `X-Forwarded-*`；`SKILLHUB_TRUST_FORWARDED_PROTO=true` 只在
  可信 TLS 终止代理场景开启。Cookie 的 Secure、SameSite、Domain 和 Path 由最终 HTTPS
  拓扑验证。
- Client secret、LDAP bind password、签名密钥和 Broker 管理凭据放 Secret Manager；不写
  入 Git、镜像层、ConfigMap、Issue/PR 评论或普通日志。
- 限制 discovery/JWKS/token/userinfo 的出站网络和超时；配置变更先在隔离环境验证。
- 日志只允许 request id、registration id、低基数 reason code 和耗时；禁止 authorization
  code、state、nonce、Cookie、Bearer token、完整 claims 和上游响应。
- 完全移除或禁用 Broker registration 时，SkillHub `/api/v1/auth/methods` 不应展示它，且
  不应连接 discovery/JWKS。错误 issuer、错误 audience、过期 token 和 nonce/state 失败
  必须 fail closed。
- 不要在同一个 registration id 下轮换 issuer；Secret 轮换保持 client id 和 issuer 不变，
  并按 Broker 支持的重叠窗口操作。

## 7. 无凭据验证清单

以下命令只检查部署和重定向，不执行真实登录，也不打印敏感参数。把 `BASE_URL` 和
`REGISTRATION_ID` 替换为测试值：

```bash
BASE_URL=https://skillhub.example.invalid
REGISTRATION_ID=corp

curl --fail --silent --show-error "$BASE_URL/actuator/health" | jq -e '.status == "UP"'
curl --fail --silent --show-error "$BASE_URL/api/v1/auth/methods" \
  | jq --arg id "$REGISTRATION_ID" \
      -e 'any(.data[]; .provider == $id and .methodType == "OAUTH_REDIRECT")'
curl --silent --show-error --dump-header - --output /dev/null \
  "$BASE_URL/oauth2/authorization/$REGISTRATION_ID" \
  | awk 'BEGIN{IGNORECASE=1} /^Location:/ {print $0}' \
  | grep -E 'https://[^[:space:]]+'
```

随后用测试账号完成一次浏览器登录，并人工确认：首次登录只按 configured provisioning
policy 创建/审批；重复登录得到同一平台用户；改 display name/email 不违反 Profile Sync；
email collision 显示 `LINK_REQUIRED` 且没有新 Binding；登出后旧 Session 失效。检查应用日志
和审计记录中没有上面列出的 secret-bearing 值。最后以旧版本镜像做一次只读回归，再决定
是否推广到 `main`。

## 8. 升级、回滚和故障定位

本 Broker 指南不新增数据库迁移。升级时保留原有 registration id、issuer 和 client id，
因此已有 OIDC Binding 可以继续解析；只轮换 secret，不改变身份域。回滚时恢复之前的
SkillHub 镜像和同一 OIDC 配置，验证 GitHub/GitLab/OIDC、local password、Device Flow 和
API token；不要删除 Binding 或用新 issuer “修复”登录问题。

| 现象 | 首先检查 | 不要做 |
| --- | --- | --- |
| Provider 不在登录目录 | client id/secret 是否真实、issuer discovery 是否可读、registration id 是否唯一 | 直接关闭 Authority Lock 或把 issuer 改成请求参数 |
| 回调 `invalid_state`/`invalid_nonce` | 代理是否覆盖 `X-Forwarded-*`、Cookie Domain/SameSite/Secure、浏览器是否保留 Cookie | 放宽 CSRF、关闭 state/nonce 校验 |
| `AUTHORITY_MISMATCH` | 当前 issuer 是否与已绑定身份完全一致 | 复用另一个 realm 的 registration id |
| `LINK_REQUIRED` | 目标账号是否需要显式 Identity Link、email 是否未验证 | 按 email 自动绑定或合并 |
| 用户能登录但权限过高 | Broker groups/roles 是否被错误映射 | 直接把 group claim 映射为 `SUPER_ADMIN` |

## 9. 官方参考

以下链接是协议或产品的官方文档；版本细节以部署时的对应版本为准：

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OAuth 2.0 Authorization Code with PKCE (RFC 7636)](https://www.rfc-editor.org/rfc/rfc7636.html)
- [Keycloak Server Administration — LDAP user federation](https://www.keycloak.org/docs/latest/server_admin/index.html#_ldap)
- [Keycloak Server Administration — OIDC identity providers](https://www.keycloak.org/docs/latest/server_admin/index.html#_oidcv1-0-identity-providers)
- [authentik OAuth2/OIDC provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
- [authentik LDAP source](https://docs.goauthentik.io/users-sources/sources/protocols/ldap/)
- [Dex LDAP connector](https://dexidp.io/docs/connectors/ldap/)
- [Dex SAML connector](https://dexidp.io/docs/connectors/saml/)
- [Dex OIDC connector](https://dexidp.io/docs/connectors/oidc/)

SAML、Kerberos/SPNEGO、SCIM 仍按统一身份设计中的独立阶段推进；本指南不会暗示
SkillHub 已原生实现这些协议。
