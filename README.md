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

## 免责声明

接口与客户端常量来自公开 App 客户端分析，随时可能变更。  
本项目与领克汽车 / 吉利汽车无官方关联。使用风险自负。

## License

[MIT](./LICENSE)
