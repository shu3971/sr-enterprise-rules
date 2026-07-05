# Shadowrocket Enterprise Rules 2.0

智能分流企业版规则系统

## 订阅链接

| 配置 | CDN 链接 |
|------|----------|
| 完整版 | `https://cdn.jsdelivr.net/gh/shu3971/sr-enterprise-rules@main/build/main.conf` |
| 轻量版 | `https://cdn.jsdelivr.net/gh/shu3971/sr-enterprise-rules@main/build/lite.conf` |
| AI 专用 | `https://cdn.jsdelivr.net/gh/shu3971/sr-enterprise-rules@main/build/ai.conf` |

## 规则说明

| 文件 | 策略 | 说明 |
|------|------|------|
| core.txt | DIRECT | 国内常用服务（微信、抖音、淘宝、GitHub 等） |
| accelerate.txt | DIRECT | CDN 加速域名 |
| ai.txt | PROXY | AI 服务（OpenAI、Anthropic、Google 等） |
| video.txt | PROXY | 流媒体（YouTube、Netflix、TikTok） |
| game.txt | PROXY | 游戏平台（Steam、PS、Nintendo、Xbox） |
| privacy.txt | REJECT | 隐私追踪（Adjust、AppsFlyer 等） |
| adblock.txt | REJECT | 广告拦截（穿山甲、广点通、友盟） |

## 构建

```bash
python3 scripts/build.py
```
