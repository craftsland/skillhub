---
title: 安全扫描
sidebar_position: 4
description: 使用 Skill Scanner 为技能发布链路提供自动安全检查
---

# 安全扫描

SkillHub 支持在技能发布链路中接入 `skill-scanner`，对上传的技能包执行自动安全检查，并把结果沉淀到安全审计记录中。

## 扫描链路

启用扫描后，发布流程会变成：

1. 用户发起技能发布
2. 后端创建版本记录并进入 `SCANNING`
3. 后端写入扫描任务
4. `skill-scanner` 拉取任务并执行分析
5. 扫描结果写入 `security_audit`
6. 版本进入 `PENDING_REVIEW`，如多次重试后仍失败则进入 `SCAN_FAILED`
7. 后续仍然沿用已有的审核工作流

## 适用场景

- 企业希望在人工审核前增加一层自动风险筛查
- 平台需要保留技能包扫描结果和审计证据
- 部署环境要求对恶意代码、敏感信息或高风险行为做基础检测

## 运行模式

支持两种模式：

- `local`：后端把文件路径传给扫描服务，适合同机或共享文件系统场景
- `upload`：后端直接上传技能包到扫描服务，适合 Docker / Kubernetes 等分离部署场景

推荐做法：

- 本地开发：优先使用 `local`
- 生产环境、Kubernetes、多服务部署：优先使用 `upload`

## 关键配置

后端核心配置项：

```yaml
skillhub:
  security:
    scanner:
      enabled: false
      base-url: http://localhost:8000
      health-path: /health
      scan-path: /scan-upload
      mode: upload
      connect-timeout-ms: 5000
      read-timeout-ms: 300000
      retry-max-attempts: 3
```

常用环境变量：

- `SKILLHUB_SECURITY_SCANNER_ENABLED`
- `SKILLHUB_SECURITY_SCANNER_URL`
- `SKILLHUB_SECURITY_SCANNER_MODE`
- `SKILLHUB_SCAN_STREAM_KEY`
- `SKILLHUB_SCAN_STREAM_GROUP`

## 验证方式

启用后建议按下面步骤验证：

1. 发布一个测试技能包
2. 确认版本状态先进入 `SCANNING`
3. 确认生成了 `security_audit` 记录
4. 确认版本最终进入 `PENDING_REVIEW` 或 `SCAN_FAILED`
5. 调用安全审计接口查看扫描结果

```text
GET /api/v1/skills/{skillId}/versions/{versionId}/security-audit
```

## 结果说明

安全审计结果通常包含：

- `scanId`
- `scannerType`
- `verdict`
- `isSafe`
- `maxSeverity`
- `findingsCount`
- `findings`
- `scanDurationSeconds`
- `scannedAt`

## 部署建议

- 单机开发环境可先关闭扫描，确认主流程后再开启
- Kubernetes 中建议使用 `upload` 模式，避免服务间共享文件系统
- 生产环境建议把扫描结果与人工审核一起作为治理证据保留

## 下一步

- [审核工作流](../governance/review-workflow) - 了解扫描后的审核链路
- [部署配置](../deployment/configuration) - 查看部署相关配置
