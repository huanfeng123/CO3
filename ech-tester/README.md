# ECH Handshake Tester

独立 Android ECH 握手测试工具。它从 DoH 查询配置来源域名的 HTTPS 记录，
提取 `ech=` 配置，再连接目标域名执行 TLS 1.3 + ECH 握手。

## 功能

- 配置来源域名和目标域名可以不同
- 可编辑 `public_name` 和内层 `sni`
- 可选 DoH 地址与连接 IP
- 显示可复制的完整握手日志
- GitHub Actions 只构建 `arm64-v8a` APK

`public_name` 会改写 ECHConfigList 中的公有名称。服务器是否接受该组合，
以最终的 `ECHAccepted=true` 和 TLS 握手结果为准。

## 本地构建

需要 Go 1.24、Java 17、Android SDK/NDK，以及 `gomobile`：

```sh
cd ech
go get golang.org/x/mobile/bind@latest
gomobile bind -target=android/arm64 -androidapi 24 \
  -o ../android/app/libs/echtester.aar ./echtester
cd ../android
./gradlew assembleRelease
```

