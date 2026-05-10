# KaLogin CatSeedLogin 兼容版说明

本版本在原 KaLogin 基础上新增了 `catseed-sqlite` 数据库模式，用于读取 CatSeedLogin 的 `accounts.db`。

## 推荐配置

```yml
use-AuthMe: false

database:
  type: "catseed-sqlite"

catseed:
  sqlite-file: "D:\\服务器\\[25566] 登录服\\plugins\\CatSeedLogin\\accounts.db"
  table: "accounts"
  readonly: true
  username-ignore-case: true
  columns:
    username: "name"
    password: "password"
    ips: "ips"
    last-action: "lastAction"
  messages:
    not-registered: "&c账号不存在，请先在旧登录服或官网完成注册。"
```

## 行为

- 已存在于 CatSeedLogin `accounts` 表的玩家，可以直接使用原 CatSeedLogin 密码登录。
- 密码校验方式：`SHA-512(玩家输入密码)`，与 `accounts.password` 比较。
- `readonly: true` 时不会写入 CatSeedLogin 数据库。
- `readonly: true` 时，未注册玩家不会进入 KaLogin 注册流程，而是直接踢出并提示注册说明。
- `readonly: true` 时，修改密码、后台重设密码、删除账号会失败，避免写坏旧库。

## 注意

1. 1.21.8 专属登录服建议使用 Paper 1.21.8。
2. 不建议 CatSeedLogin 和 KaLogin 同时写同一个 SQLite 文件。
3. 如果后续要支持注册/改密，建议先把账号库迁移到 MySQL，或确保只有一个服务负责写入。
4. 原项目构建需要联网下载 Gradle / Paper API / Kotlin Gradle Plugin；如果离线环境构建，请先准备 Gradle 缓存。


## v1.3.6-catseedhash 修复说明

CatSeedLogin 1.3.5 的密码不是 `SHA512(password)`，而是：

```text
SHA512("??aeut//&/=I" + password + "7421?547" + name + "__+I?IH?%NK" + password)
```

其中 `name` 是 CatSeedLogin 数据库 `accounts.name` 中保存的玩家名。
本兼容版在校验密码时会同时读取 `accounts.name` 和 `accounts.password`，用数据库中的名字参与 hash，避免大小写不一致导致老密码无法登录。

Windows 路径建议使用：

```yml
catseed:
  sqlite-file: 'D:/服务器/[25566] 登录服/plugins/CatSeedLogin/accounts.db'
```
