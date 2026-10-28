# signscan

> 从安装包 exe 中提取 Authenticode 签名证书。

## 用法

```powershell
./scripts/publish.ps1
./artifacts/publish/signscan.exe --input-dir <dir> --output-dir <dir>
```

- 递归扫描 `.exe`(大小写不敏感),不扫描 dll/sys/msi/脚本
- 输出按输入顶层目录拓平:
  `input/A/A1/x.exe` → `output/A/<开始日期>-<结束日期>-<证书SHA256>.cer`
- 同一顶层目录内按证书去重
- 读取全部签名,包括 `signtool /as` 生成的嵌套签名
- 证书用 DER 写出;日期用 UTC;哈希为证书 DER 的 SHA-256
- 只有 catalog 签名、没有内嵌 PKCS#7 的 exe 会跳过
- 位于输入根目录的 exe 归入 `others`

## 开发

- .NET SDK 10(`global.json` 锁定 10.0.403)
- NativeAOT 发布需要 Visual Studio 2022 Build Tools 的 MSVC 工具集与 Windows SDK

```powershell
dotnet restore
dotnet build
dotnet test
./scripts/publish.ps1
```
