# ⭐⭐⭐⭐⭐   ![to02x-362ea](https://github.com/user-attachments/assets/55f1bb83-5527-4958-8770-bbb444c2f92f)⭐⭐⭐⭐⭐



## 更多关于本项目的介绍，请前往公众号获取更详细使用教程：

**[ZeroEye](https://mp.weixin.qq.com/s/D0x4XSr37cMrv7Y4ScRqTg)** 一款自动化白加黑扫描工具，支持原生PE、.NET程序、内核驱动三种类型的扫描与利用模板生成。

### 存在其他问题请提交**Issues**

###  ⭐确定不来一个吗？

---

# 功能概览

| 功能 | 说明 |
|------|------|
| **原生PE扫描** | 扫描EXE导入表，自动复制非系统DLL，生成代理DLL模板 |
| **.NET程序扫描** | 自动识别.NET程序，分析Config劫持/P/Invoke/Assembly侧加载向量 |
| **.NET Config劫持** | 自动生成AppDomainManager注入config + payload源码，即开即用 |
| **内核驱动扫描** | 扫描第三方驱动的IOCTL + 危险API（自动跳过微软签名驱动） |
| **C++类重建引擎** | 从MSVC修饰名反向重建C++类结构，生成3种代理DLL模板 |
| **类型过滤扫描** | `-t` 参数支持按类型扫描：gui/cmd/dotnet/sys，可组合 |
| **自动检测** | `-i` 和 `-d` 自动识别原生PE/.NET，无需手动判断 |

---

# 参数说明

```
用法: ZeroEye [选项]
选项:
  -h   <帮助|示例>                  显示帮助信息
  -i   <PE 文件>                    分析PE文件 (自动识别 原生/.NET)
  -p   <目录>                       扫描指定目录下的可疑程序
  -s   <签名检查>                   仅扫描有数字签名的程序
  -e   <排除EXE>                    排除仅依赖系统DLL的程序
  -d   <PE 模块>                    生成劫持模板 (自动识别 原生/.NET)
  -x   <架构>                       指定扫描架构 (64/86)
  -g   <排除列表>                   排除指定DLL (用|分隔)
  -t   <类型>                       扫描类型: gui,cmd,exe,dotnet,sys,all (默认: all)
  -IM  <PE 文件>                    查看导入表
  -EX  <PE 文件>                    查看导出表

示例:
  ZeroEye.exe -i a.exe                                          分析PE文件 (自动识别原生/.NET)
  ZeroEye.exe -d a.dll                                          生成劫持模板 (自动识别原生/.NET)
  ZeroEye.exe -p c:\                                            扫描C盘 (全类型)
  ZeroEye.exe -p c:\ -t gui                                     仅扫描GUI程序
  ZeroEye.exe -p c:\ -t dotnet                                  仅扫描.NET程序
  ZeroEye.exe -p c:\ -t sys                                     仅扫描内核驱动
  ZeroEye.exe -p c:\ -t gui,dotnet -s -x 64                     扫描已签名的64位 GUI+.NET程序
  ZeroEye.exe -p c:\ -s -x 64 -g "api-ms|ucrtbase" -e          扫描已签名64位 仅系统依赖
  ZeroEye.exe -IM/-EX a.dll                                     查看导入/导出表
```

---

# 输出目录结构

## 原生PE（白加黑）
```
Eyebin/Dll/x64/
└── notepad++[gui-5-3.2MB]/
    ├── notepad++.exe                    ← 目标程序
    ├── SciLexer.dll                     ← 可劫持DLL
    └── infos/
        └── Info.txt                     ← 分析结果
```

## .NET程序
```
Eyebin/Dll/x64/
└── GitHubProtocolHandler[dotnet-2-1.1MB]/
    ├── GitHubProtocolHandler.exe        ← 目标程序
    ├── GitHubProtocolHandler.exe.config ← 已替换为劫持config
    ├── GitHubProtocolHandler.exe.config.bak ← 原始config备份
    ├── *.dll                            ← 引用的依赖DLL
    └── infos/
        ├── Info.txt                     ← 分析结果
        ├── GitHubProtocolHandler.config ← 劫持config模板
        └── GitHubProtocolHandler_payload.cs ← payload源码
```

.NET 使用流程：
```
1. cd 到输出文件夹
2. csc /target:library /out:zeroeye_payload.dll /ref:System.Windows.Forms.dll infos\xxx_payload.cs
3. 运行 xxx.exe → 弹窗验证劫持成功
```

## 内核驱动
```
Eyebin/Sys/
└── dbutil_2_3[sys-50KB]/
    ├── dbutil_2_3.sys                   ← 驱动文件
    └── infos/
        └── Info.txt                     ← 签名者 + 危险API列表
```

---

# 文件夹命名规则

格式：`名称[类型-数量-大小]`

| 类型 | 含义 |
|------|------|
| `gui` | 原生GUI程序 |
| `cmd` | 原生控制台程序 |
| `dotnet` | .NET Framework |
| `dotnet-core` | .NET Core/5+ |
| `sys` | 内核驱动 |

示例：
```
notepad++[gui-5-3.2MB]          ← GUI程序，5个可劫持DLL，总大小3.2MB
cmd_tool[cmd-3-512KB]           ← 控制台程序，3个可劫持DLL
GitHandler[dotnet-2-1.1MB]      ← .NET Framework，2个劫持向量
myapp[dotnet-core-1-256KB]      ← .NET Core程序
dbutil_2_3[sys-50KB]            ← 第三方驱动，50KB
notepad++[gui-5-3.2MB](2)      ← 重复时自动编号
```

---

# 全版本介绍

* 1.0 ~ 3.0 可在Release中获取
* 3.1 修复遍历导入表空格名称、目录遍历、0xc05内存访问冲突
* 3.2 优化输出排序、禁用损坏镜像提示、LoadLibraryA改为LoadLibraryExA
* 3.3 优化扫描速度、x64/x86导入导出表、模板生成、DLL嵌套调用检测、签名校验
* 3.4 添加指定x64/x86、修复class识别错误
* 3.5 添加扫描仅需系统DLL的单文件EXE（适用于patch免杀）
* 3.6 添加控制台程序过滤、`-h`显示示例、中英双译

---

## 5.0版本（重大更新）

### 新增：.NET程序扫描与劫持

| 特性 | 说明 |
|------|------|
| **.NET自动识别** | 扫描时自动检测.NET程序（通过PE的CLR header），无需手动区分 |
| **ECMA-335元数据解析** | 解析.NET元数据表，提取ModuleRef（P/Invoke目标）和AssemblyRef（程序集引用） |
| **Config劫持检测** | 检测.exe.config是否存在（不存在 = 可创建，风险更高） |
| **AppDomainManager注入** | 自动生成config模板，使用AppDomainManager注入，绕过强签名限制 |
| **Payload源码生成** | 自动生成C#源码，一行命令编译即可验证 |
| **原始config保留** | 自动保留原始assemblyBinding，确保程序正常运行 |

### 新增：内核驱动扫描

| 特性 | 说明 |
|------|------|
| **IOCTL检测** | 检测驱动是否通过IoCreateDevice创建设备（有IOCTL接口） |
| **危险API检测** | 扫描ZwTerminateProcess、ZwOpenProcess、ZwWriteFile、ZwDeleteFile等 |
| **微软驱动过滤** | 自动跳过微软签名的系统驱动，只报告第三方驱动 |
| **签名者显示** | 输出驱动的签名者名称，方便判断来源 |

### 新增：C++类重建引擎（Method 3）

新增 **ProxyGenerator** 模块，可直接从DLL导出表反向重建完整的C++类结构，生成可直接编译的代理模板。

| 特性 | 说明 |
|------|------|
| **C++类重建** | 从MSVC修饰名解析，自动还原 class/struct/enum 声明、成员函数签名、静态数据成员 |
| **三种模板同时生成** | `_exports.cpp`（extern C桩）、`_pragma.cpp`（pragma转发）、`_class.cpp`（C++类重建+精确pragma兜底） |
| **命名空间支持** | 正确处理 `asw::root::CGenericFile` 等多级嵌套命名空间类 |
| **Singleton模板识别** | 自动检测并生成 `Singleton<T>` 模板类 |
| **类型降级+Pragma兜底** | 无法精确还原的类型自动降级为 `void*`，对应导出用pragma linker comment兜底 |

技术细节：
* 函数指针参数正确解析：同时追踪 `<>` 和 `()` 深度
* MSVC编译器内部方法过滤：自动过滤 `__autoclassinit2` 等
* 命名空间类型前向声明、签名去重、跨域类型引用降级

### 新增：递归DLL依赖链解析

| 特性 | 说明 |
|------|------|
| **链式递归复制** | exe → dll₁ → dll₂ → dll₃ → dll₄，最深4层 |
| **跨目录搜索** | DLL不在同目录时，自动向上搜索父目录及兄弟目录（最多3层） |
| **循环依赖保护** | visited集合防止同一DLL被重复处理 |
| **原始路径记录** | Info.txt中每个DLL附带完整原始路径 |

### 改进：参数系统重构

| 改进 | 说明 |
|------|------|
| **三阶段解析** | 先解析所有参数 → 处理修饰符 → 执行操作，参数顺序不再影响结果 |
| **`-i` 自动检测** | 输入原生PE显示导入DLL，输入.NET显示劫持向量 |
| **`-d` 自动检测** | 输入原生DLL生成代理模板，输入.NET程序生成config劫持模板 |
| **`-t` 类型过滤** | 替代原 `-nc`，支持gui/cmd/exe/dotnet/sys/all，可组合 |
| **SEH保护** | 单个文件崩溃不影响整体扫描，耗时始终显示 |
| **路径修复** | 修复根目录双斜杠、超长路径静默跳过 |
| **中英双语** | UTF-8中文完整翻译，自动检测系统语言 |

### 改进：输出优化

| 改进 | 说明 |
|------|------|
| **文件夹命名** | `名称[类型-数量-大小]` 格式，直观清晰 |
| **infos子目录** | 模板文件、Info.txt统一放在infos/，根目录只保留可运行文件 |
| **.NET精准复制** | 只复制元数据中引用的DLL，不复制同目录无关文件 |
| **.NET即开即用** | config自动替换，编译payload后直接运行验证 |

---

## ⭐⭐Stargazers over time ⭐⭐
[![Stargazers over time](https://starchart.cc/ImCoriander/ZeroEye.svg?variant=adaptive)](https://starchart.cc/ImCoriander/ZeroEye)
