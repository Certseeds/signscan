# signscan

> 从 PE 文件(exe/dll/sys 等)与 Windows Installer 包(msi/msp/mst)中提取 Authenticode 签名证书。

## 用法

```powershell
./scripts/publish.ps1
./artifacts/publish/signscan.exe --input-dir <dir> --output-dir <dir>
./artifacts/publish/signscan.exe --allow-dir <dir> --output-dir <dir>
```

- 递归扫描 `.exe`、`.dll`、`.sys`、`.drv`、`.ocx`、`.cpl`、`.scr`、`.msi`、`.msp`、`.mst`(大小写不敏感),不扫描脚本、`.pyd`、`.node` 等其它扩展名
- MSI/MSP/MST 签名从复合文档的 `\u0005DigitalSignature` 流读取;使用 OpenMcdf(MPL-2.0)
- 输出按输入顶层目录拓平:
  `input/A/A1/x.exe` → `output/A/<开始日期>-<结束日期>-<证书SHA256>.cer`
- 同一顶层目录内按证书去重
- 读取全部签名,包括 `signtool /as` 生成的嵌套签名
- 证书用 DER 写出;日期用 UTC;哈希为证书 DER 的 SHA-256
- 只有 catalog 签名、没有内嵌 PKCS#7 的文件会跳过
- 位于输入根目录的受支持文件归入 `others`
- `--input-dir` 与 `--allow-dir` 必须恰好提供一个,否则直接退出(退出码 2)
- `--allow-dir` 扫描白名单目录中的受支持文件,按相同命名规则,只在同名顶层分组内删除 `--output-dir` 中对应的 `.cer`;输出目录必须已存在
- 白名单证书在输出目录中不存在时给警告并计入未命中,不视为失败
- 扫描结束后在输出根目录生成 `company-app-to-cert.json` 和 `cert-to-company-app.json`
- 映射以输入相对路径前两层为 `company` / `codename`;公司下直接放的受支持文件的 codename 为 `others`,根目录文件为 `others - others`
- 同一证书被多个公司/应用使用时,反向映射合并为一条并列出全部公司与应用
- `--allow-dir` 删除证书后会同步清理映射:按公司移除该证书在所有 codename 下的引用,并重新生成两个文件;删除失败(文件被占用)的证书保留映射,映射文件不存在时跳过更新

## 开发

- .NET SDK 10(`global.json` 锁定 10.0.404)
- NativeAOT 发布需要 Visual Studio 2022 Build Tools 的 MSVC 工具集与 Windows SDK

```powershell
dotnet restore
dotnet build
dotnet test
./scripts/publish.ps1
```
