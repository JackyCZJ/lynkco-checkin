# lynkco-checkin

领克 App 登录 + 每日签到 CLI（纯 Python 标准库，可选 `pycryptodome` 仅账密登录需要）。

> 仅供学习与个人自动化使用。请遵守领克用户协议与当地法律法规；不要用于商业或滥用接口。

## 功能

- **交互登录**：本机打开浏览器完成 **GeeTest V4** → 发短信 → 输入验证码 → 保存 session  
- **签到**：`POST /up/api/v1/user/sign`  
- **刷新 token**、查签到状态、查用户信息  
- Session 默认写入 `~/.lynkco_session.json`

## 环境

- Python 3.9+
- 无需额外依赖（标准库即可）
- 账密登录才需要：`pip install pycryptodome`

## 快速开始

```bash
git clone https://github.com/JackyCZJ/lynkco-checkin.git
cd lynkco-checkin

# 登录（会弹浏览器做极验，手动点完后回终端输入短信验证码）
python3 lynkco_sign.py login -m 你的手机号

# 签到
python3 lynkco_sign.py sign

# 登录并签到
python3 lynkco_sign.py login -m 你的手机号 --sign

# 已有 accessToken 时
python3 lynkco_sign.py --token '你的token' sign

# 查状态
python3 lynkco_sign.py sign --status

# 用 refreshToken 刷新后签到
python3 lynkco_sign.py --refresh-token 'xxx' refresh
python3 lynkco_sign.py auto
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `login -m 手机号` | 浏览器极验 + 短信登录 |
| `login -m 手机号 --sign` | 登录后立即签到 |
| `captcha` | 只做极验，打印 `certifyId` |
| `sign` | 签到 |
| `sign --status` | 查签到状态 / 连续天数 |
| `refresh` | 刷新 accessToken |
| `info` | 当前用户信息 |
| `auto` | 有 token 直接签；否则 refresh 再签 |
| `geetest` | 只拉极验配置 |
| `send-sms -m 手机 --browser` | 弹极验后发短信 |

全局参数：

```text
--session PATH       会话文件（默认 ~/.lynkco_session.json）
--token TOKEN        accessToken（写在子命令前）
--refresh-token RT   refreshToken
--timeout 300        等待浏览器完成极验的秒数
```

## 登录流程说明

```text
浏览器 GeeTest V4
    → POST /auth/v1/security/geeTestV4/validate  → challenge/certifyId
    → POST /auth/login/sliding/sendSms           → 短信
    → POST /auth/login/mobileCodeLogin           → centerTokenDto.token
    → POST /up/api/v1/user/sign                  → 签到
```

注意：

- 极验 `challenge` **只用于发短信**，不要塞进登录的 `certifyId` 头（否则会 `oneid.account.certify.validate.fail`）。
- 发短信接口需要阿里云网关 **X-Ca 签名**；业务接口用 `APPCODE` + header `token`。

## 已知缺陷与限制

以下为实际使用中确认的问题，**短期内不打算继续挖抓包/共存**；能用脚本交互登录签到即可。

### 1. 多端登录互踢（严重）

| 现象 | 服务端返回 |
|------|------------|
| 手机重新登录后，脚本 session 失效 | `user-crowded-out` / `user-login-invalid-expired` |
| refresh 也救不回来 | `user-crowded-out`（文案：**已在其他设备登录，请重新登录**） |

- 账号侧基本是 **单会话/强互踢**，不是简单的「网关 APPCODE 不一样」。
- **复制手机相同的 `deviceId` 不能稳定解决共存**：更像按账号会话踢人，而不是「同 device 双开」。
- 结果：脚本签到与手机正常用 App **很难长期并行**；谁后登录，谁留下。

### 2. 无法用 mitm / 用户 CA 从 App 抠 token

| 手段 | 结果 |
|------|------|
| mitmproxy / Reqable / PCAPdroid 代理 + 用户 CA | 领克 App **一开代理就无法正常联网** |
| PCAPdroid 导出 CSV | 只有连接元数据（域名/字节数），**无 HTTP Header/Body，无 token** |
| 非 root ADB 读 App 私有目录 | 包 **非 debuggable**，读不到 MMKV 里的登录态 |

根因是客户端 **不信任用户 CA / 有证书校验（pinning 一类）**，不是 mitm 配置问题。  
在不 root、不解 SSL pin 的前提下，**不能**从手机抓包稳定导出 `token` 给脚本用。

### 3. 登录必须人机交互（无法纯无人值守登录）

- 发短信依赖 **GeeTest V4**，脚本用本机起页 + **浏览器手动点滑块**。
- 之后还要 **人工输入短信验证码**。
- **Cron / 定时任务不能自动完成 login**，只能在已有有效 `~/.lynkco_session.json` 时跑 `sign` / `auto`。
- token 过期或被挤掉后，必须本机再跑一次 `login`。

### 4. 极验 challenge 与登录 certifyId 易用错

- `challenge` / 极验 `certifyId` **只给** `sliding/sendSms` 用。
- 短信登录主路径 **不应** 再把该 id 塞进 header `certifyId`，否则常见：  
  `oneid.account.certify.validate.fail`（验证码其实对，是 certify 校验挂了）。
- 脚本当前默认登录不带该头；自己拼请求时注意。

### 5. 客户端版本与接口漂移

- 网关常量（`APPCODE`、`X-Ca-Key`、签名密钥、`tenantId` 等）来自某版 App/Weex，**官方随时可能更换**。
- 手机商店版与逆向时版本可能不一致（例如商店 4.1.x vs 其它包 4.2.x），接口行为以线上为准。
- 签到/登录路径变更后，脚本可能直接 4xx/业务码失败，需再跟包更新。

### 6. 抓包工具在新系统上的坑（实践记录）

| 工具 | 问题 |
|------|------|
| HttpCanary 老包 / 魔改包 | 在 **Android 16** 上 `VerifyError` **秒闪退**（ART 拒掉损坏/过时字节码） |
| Reqable | 新系统上 **用户 CA 安装流程经常走不通** |
| PCAPdroid 默认导出 CSV | 无 TLS 明文，对抠 token **没用** |

### 7. 安全与合规（使用层面）

- Session 文件含长期凭证，勿提交到 Git、勿发群。
- 仅供个人学习/自用自动化；滥用接口、绕过风控可能违规并导致封号。
- 本仓库 **不提供** root 解 pin、改包、绕过官方安全机制的教程。

### 可行工作流（在缺陷下）

```text
1. 本机：python3 lynkco_sign.py login -m 手机号   # 浏览器极验 + 短信
2. 签到：python3 lynkco_sign.py sign / auto
3. 手机尽量少「重新登录」，以免挤掉脚本 session
4. 一旦 crowded-out / expired → 重复步骤 1
5. 定时任务仅在 session 有效时跑 sign；失效就停，别盲刷
```

## 免责声明

接口与客户端常量来自公开 App 客户端分析，随时可能变更。  
本项目与领克汽车 / 吉利汽车无官方关联。使用风险自负。

## License

[MIT](./LICENSE)
