# LinkForge

LinkForge is a DLL injection tool based on Manual Mapping.

## Features
- Uses manual mapping technology to bypass traditional `LoadLibrary` injection detection
- Supports automatic target process lookup by process name
- Compatible with both 32-bit and 64-bit DLLs
- Lightweight and easy to use

## Usage
```sh
LinkForge.exe <dllPath> [processName]
```
- `dllPath`: Path to the DLL file to be injected
- `processName` (optional): Name of the target process (e.g., `notepad.exe`). If not specified, default value will set `notepad.exe`.

### Examples
#### Inject `test.dll` into `notepad.exe` process
```sh
LinkForge.exe C:\path\to\test.dll notepad.exe
```

#### Manually select a process and inject `test.dll`
```sh
LinkForge.exe C:\path\to\test.dll
```

## Compilation Requirements
- Windows platform
- C++17 or later
- Requires `Windows.h` and related API headers

## Notes
- **Ensure you have sufficient permissions for the target process, otherwise injection may fail.**
- **Some antivirus software may detect and block this operation. Adjust security settings as needed.**
- **This tool is for educational and research purposes only. Do not use it for illegal activities!**

## License
MIT License




# LinkForge

LinkForge 是一个基于手动映射 (Manual Mapping) 的 DLL 注入工具。

## 特性
- 采用手动映射技术，绕过传统 `LoadLibrary` 注入检测
- 支持通过进程名自动查找目标进程
- 兼容 32 位和 64 位 DLL
- 轻量级、易于使用

## 使用方法
```sh
LinkForge.exe <dllPath> [processName]
```
- `dllPath`：要注入的 DLL 文件路径
- `processName`（可选）：目标进程名称（如 `notepad.exe`）。如果不指定，默认使用 `notepad.exe`。

### 示例
#### 向 `notepad.exe` 进程注入 `test.dll`
```sh
LinkForge.exe C:\path\to\test.dll notepad.exe
```

#### 手动选择进程并注入 `test.dll`
```sh
LinkForge.exe C:\path\to\test.dll
```

## 编译要求
- Windows 平台
- C++17 及以上
- 需要 `Windows.h` 及相关 API 头文件

## 注意事项
- **请确保拥有目标进程的足够权限，否则可能会注入失败。**
- **某些杀毒软件可能会检测和拦截此类操作，请根据需要调整防护策略。**
- **本工具仅供学习和研究使用，请勿用于非法用途！**

## 许可证
MIT License

