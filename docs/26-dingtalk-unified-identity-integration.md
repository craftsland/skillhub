# DingTalk 与统一身份核心集成设计

> 适用范围：维护者 Issue [#675](https://github.com/iflytek/skillhub/issues/675)。
>
> 本文件描述 DingTalk Native OAuth2 Browser Adapter 的协议、信任边界、部署和验收。
> 它不替代统一身份核心的领域规则；账号、身份绑定、账号合并、角色和 Session 的唯一
> 入口仍是 `skillhub-auth` 中现有的 Registry 与 Identity Services。

## 1. 目标与非目标

### 1.1 目标

- 支持 DingTalk 官方 authorization-code OAuth2 浏览器登录。
- 将 DingTalk 响应转换成协议无关的 `ProviderAuthenticationResult`。
- 让同一个 DingTalk 身份经过现有 Provider Registry、`ExternalIdentityLoginService`、
  Identity Link 和 Account Merge 流程解析到同一个平台账号。
- 在启动和运行时都对 Provider Instance、固定 endpoint、响应大小、超时和稳定 subject
  实施 fail-closed 校验。
- 让 provider disabled/incomplete 时从登录目录隐藏，并且在隐藏状态不访问 DingTalk。

### 1.2 非目标

- 适配器不能创建 `UserAccount`、`PlatformPrincipal`、角色、权限或 Session。
- 不能根据 DingTalk email 自动绑定已有账号，也不能把普通 email 当作 verified email。
- 不能从 DingTalk response 推导 SkillHub authority、租户、平台角色或管理员身份。
- 不修改外部贡献者 PR [#467](https://github.com/iflytek/skillhub/pull/467) 的提交。
- 不在 `main` 上直接验证或合并；先进入 `big-main`，再做独立香港测试环境验证。

## 2. 信任模型

SkillHub 把外部登录拆成三个层次：

```text
DingTalk protocol response
        │  (native adapter: transport + shape validation)
        ▼
ProviderAuthenticationResult
        │  (trusted ProviderDescriptor from server configuration)
        ▼
IdentityAssertion / identity binding / account merge / platform session
```

适配器只负责第一层到第二层。第二层到第三层必须由统一身份核心完成，原因是：

1. 账号绑定需要事务、冲突检测、link intent 和一次性 proof。
2. 同一个 subject 必须经过 server-owned provider authority 才能形成全局唯一坐标。
3. 角色和 Session 是 SkillHub 的安全状态，不能由外部 IdP 的可变字段决定。

### 2.1 Provider Instance 与 authority

DingTalk 的 registration id 固定为 `dingtalk`。运维配置的
`SKILLHUB_AUTH_DINGTALK_AUTHORITY` 是 SkillHub 内部稳定的身份命名空间，例如
`dingtalk.corp`；它不是 URL，不从 `unionId`、`openId`、email 或任意上游 claim 读取。

产生身份绑定后不得修改 authority。若需要迁移到另一个 DingTalk 应用或租户，应通过显式
的 Identity Link/迁移流程证明两边账号控制权，不能覆盖旧 binding。

### 2.2 Subject 规则

| DingTalk 字段 | SkillHub 类型 | 用途 | 信任要求 |
| --- | --- | --- | --- |
| `unionId` | `dingtalk_union_id` | primary subject | 必须存在、非空、原样保留 |
| `openId` | `dingtalk_open_id` | typed alternate subject | 仅接受同一已验证响应中的值 |
| `userId` | `dingtalk_user_id` | typed alternate subject | 仅接受同一已验证响应中的值 |

`unionId` 缺失时整个登录失败；不能退回使用 `openId` 或 `userId` 作为 primary。三种
subject 都使用 `EXACT` canonicalizer，大小写和字符不能被静默改写。alternate 只能用于
统一核心已有的受控查找/迁移语义，不能绕过 authority 或 Link proof。

### 2.3 Profile 与 email

适配器只映射以下非敏感属性：

- `nick` → `dingtalk_nick`
- `name` → `dingtalk_name`
- `email` → `dingtalk_email`
- `avatarUrl` → `dingtalk_avatar_url`

属性值只接受无首尾空白的字符串。DingTalk 普通 OAuth userinfo 返回的 email 标记为
`ProviderAttributeTrust.ASSERTED`，Registry 将其上限钳制为 `PROVIDER_ASSERTED`。它不能
触发 email 自动绑定，也不能作为 verified/authoritative 邮箱。头像仍由统一核心执行
HTTP(S) URI 校验；适配器不保存 raw response。

## 3. 协议适配器

实现位于 `server/skillhub-auth/.../oauth/`：

- `DingTalkTokenResponseClient`：以 JSON body 发送 `clientId`、`clientSecret`、`code`、
  `grantType=authorization_code`，解析 `accessToken` 与正整数 `expireIn`。
- `DingTalkOAuth2UserService`：固定调用 userinfo endpoint，并使用
  `x-acs-dingtalk-access-token` header，不使用标准 `Authorization: Bearer` 传输。
- `DingTalkClaimsExtractor`：只把已验证的 userinfo facts 转成统一核心输入。
- `ProviderAware*`：只按 registration id 将 DingTalk 请求路由到 native adapter，其他
  OAuth/OIDC registration 保持原有 Spring Security delegate。

固定 endpoint：

```text
authorization: https://login.dingtalk.com/oauth2/auth
token:         https://api.dingtalk.com/v1.0/oauth2/userAccessToken
userinfo:      https://api.dingtalk.com/v1.0/contact/users/me
```

所有 endpoint 都必须与 server-owned `ClientRegistration` 完全一致。重建的 registration、
改变的 user-name attribute、非 authorization-code grant 或任意 endpoint 偏差均 fail closed。

### 3.1 响应边界

- connect/read timeout 必须为正且不超过 1 分钟。
- response body 默认最多 1 MiB，允许范围为 1 KiB–1 MiB。
- HTTP 错误、空 body、超限 body、非法 JSON、缺少 token、非法 `expireIn` 或缺少
  `unionId` 都转换成稳定 OAuth 错误码，不回显响应 body。
- access token、client secret、authorization code 和 raw response 不进入
  `ProviderAuthenticationResult`、日志或审计字段。
- provider disabled 或 registration 不完整时，在任何 HTTP 调用前失败。

## 4. 配置与部署

### 4.1 Compose / release 环境变量

```text
SKILLHUB_AUTH_DINGTALK_ENABLED=false
SKILLHUB_AUTH_DINGTALK_AUTHORITY=dingtalk.corp
SKILLHUB_AUTH_DINGTALK_CONNECT_TIMEOUT=PT5S
SKILLHUB_AUTH_DINGTALK_READ_TIMEOUT=PT10S
SKILLHUB_AUTH_DINGTALK_MAX_RESPONSE_BYTES=1048576
OAUTH2_DINGTALK_CLIENT_ID=
OAUTH2_DINGTALK_CLIENT_SECRET=
OAUTH2_DINGTALK_DISPLAY_NAME=DingTalk
```

启用前必须同时提供非 placeholder 的 client id、client secret、authority、timeout 和
response limit。`scripts/validate-release-config.sh` 会拒绝不完整凭据、非法 authority
字符和越界 response limit。

在 Compose 中，client credentials 通过环境变量注入容器；在 Kubernetes 中，authority 和
边界参数进入 ConfigMap，client id/secret 进入 Secret。不要把 Secret 提交到仓库或写入
ConfigMap。默认关闭意味着普通部署不会产生 DingTalk 网络流量。

### 4.2 启用步骤

1. 在 DingTalk 管理端创建 OAuth 应用并配置与 SkillHub 完全一致的回调 URI：
   `/login/oauth2/code/dingtalk`（由 Spring `{baseUrl}` 展开）。
2. 在 secret store 写入 `OAUTH2_DINGTALK_CLIENT_ID` 和
   `OAUTH2_DINGTALK_CLIENT_SECRET`。
3. 设置稳定的 `SKILLHUB_AUTH_DINGTALK_AUTHORITY`，确认该值尚未用于另一套 IdP。
4. 运行 release config validator 和 Kustomize/Compose 配置渲染检查。
5. 在 `big-main` 的精确 SHA 镜像上先部署，确认 provider 目录出现 DingTalk；再执行
   operator smoke 和人工 callback 验证。
6. 只有远端验证通过、现有服务健康且本次资源已清理后，才向维护者申请合入 `main`。

## 5. 升级、绑定与回滚

### 5.1 老版本兼容性

本功能只增加代码、配置和登录目录项，不改变现有 GitHub、GitLab、OIDC、LDAP、CAS、
local password、API token、Identity Link 或 Account Merge 的数据结构。禁用 DingTalk
时老版本无需识别新环境变量即可继续运行。

新版本升级不迁移、不删除既有 `identity_binding`。DingTalk 的第一次登录如果找不到
binding，遵循现有 provider provisioning policy；若 email 与已有账号冲突，进入统一核心
的 link-required 流程，而不是自动合并。已存在的旧绑定不会因为 profile name/email 变化
而改变 subject。

### 5.2 回滚

回滚前先把 `SKILLHUB_AUTH_DINGTALK_ENABLED=false` 部署到所有新 Pod，并确认登录目录不再
提供 DingTalk。保留已有 identity binding 和审计数据；不要删除 binding、直接改 authority、
恢复角色或手工改库。旧镜像忽略新环境变量即可回滚到不支持 DingTalk 的版本。

## 6. 验收矩阵

### 6.1 自动检查

```bash
./mvnw -pl skillhub-auth -am test
bash scripts/tests/validate-release-config-test.sh
make test-backend-app
make typecheck-web
make lint-web
make staging
```

适配器测试必须覆盖：

- unionId primary、openId/userId typed aliases；
- 缺少 unionId、非法 JSON、HTTP error、空/超限响应；
- 非正或超长 token expiry；
- DingTalk 自定义 token header 和官方 endpoint；
- disabled/incomplete provider 在网络调用前失败；
- Provider Registry 对三种 subject 使用 `EXACT`，email 上限为
  `PROVIDER_ASSERTED`；
- adapter bytecode 不依赖账号、principal、role、session 或 persistence 类。

### 6.2 香港测试机最小人工路径

在不重启宿主机、不中断现有 `skillhub-runtime-*` 的前提下，使用独立 project/network/
container name 部署精确 SHA：

1. `GET /actuator/health` 返回 200，provider catalog 在 disabled 时不包含 DingTalk。
2. 启用 mock DingTalk transport 后，登录 callback 只创建/解析统一核心允许的结果；重复
   `unionId` 登录解析到同一 binding。
3. 修改 `nick`/`email` 不改变 `dingtalk_union_id`；普通 email 不能自动绑定冲突账号。
4. Identity Link 和 Account Merge 仍要求现有一次性 state/proof，不能通过重复 callback
   或换 openId 绕过。
5. 检查容器日志、响应和审计中没有 client secret、authorization code、access token、
   raw response 或 session/nonce。
6. 验证完成后只删除带本次 run id 的容器、网络、镜像和临时文件；不删除 multica 历史
   记录、共享卷、其他测试资源，也不重启机器。

### 6.3 证据

进入 `main` 前应保留：feature SHA、`big-main` SHA、OCI revision、自动测试输出、配置
validator 输出、远端 health/smoke 输出、provider catalog 前后差异、日志脱敏检查和
精确清理清单。任何一项缺失都保持 DingTalk 关闭。

## 7. 参考标准

- [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [Spring Security OAuth2 Client](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html)
- [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
