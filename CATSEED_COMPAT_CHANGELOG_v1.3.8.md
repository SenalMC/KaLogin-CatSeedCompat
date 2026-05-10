# KaLogin-CatSeedCompat v1.3.8

## 修复

1. CatSeedLogin 兼容模式写入 `lastAction` 时，改为 `yyyy-MM-dd HH:mm:ss.SSS` 格式。
   - 修复旧 CatSeedLogin 读取缓存时报错：`Error parsing time stamp`。
   - 影响位置：注册、登录后更新 IP/时间、修改密码。

## 新增

2. 登录完成后执行指令。
   - 触发时机：正常登录成功、注册成功、自动登录成功。
   - 支持开关。
   - 支持控制台或玩家身份执行。
   - 支持占位符：`%player%`、`%uuid%`、`%ip%`。

配置示例：

```yml
after-login-commands:
  enabled: true
  command-mode: "console"
  commands:
    - "server 主大厅"
```

如果 `server 主大厅` 在你的环境里只能由玩家执行，可改为：

```yml
after-login-commands:
  enabled: true
  command-mode: "player"
  commands:
    - "server 主大厅"
```
