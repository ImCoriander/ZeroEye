# ⭐⭐⭐⭐⭐   ![to02x-362ea](https://github.com/user-attachments/assets/55f1bb83-5527-4958-8770-bbb444c2f92f)⭐⭐⭐⭐⭐



## 更多关于本项目的介绍，请前往公众号获取更详细使用教程：

**[ZeroEye](https://mp.weixin.qq.com/s/D0x4XSr37cMrv7Y4ScRqTg)** 用于扫描 EXE 文件的导入表，列出导入的DLL文件，并筛选出非系统DLL，符合条件的文件将被复制到特定的 **bin**  文件夹，并生成 **Infos.txt** 文件记录DLL信息。自动化找白文件，灰梭子好搭档！！！

**[灰梭子](https://mp.weixin.qq.com/s?__biz=MzkyNDUzNjk4MQ==&mid=2247483925&idx=1&sn=7424113417378915f17155260bdeef67&chksm=c1d51beff6a292f9cbb906cbaa2a55925d7ac1faeb9860b2d340b95cd33a2a0478d494daf711&scene=21#wechat_redirect)** 快速对dll进行解析函数名，并且生成对应的劫持代码，实现快速利用vs进行编译，提供了劫持模板，可前往获取。

### 存在其他问题请提交**lssues**

###  ⭐确定不来一个吗？

---

# 全版本介绍：

* 1.0 可在Release中获取
* 2.0 可在Release中获取
* 3.0 **船新版本**将不再在以上基础上更新，以后将完全使用c++完成所有操作！！！
* 3.1 修复bug
* 3.2 优化输出和禁用损坏映像提示
* 3.3 优化扫描速度、同时支持x64 or x86导入导出表、模板生成、检测dll嵌套调用、签名校验
* 3.4 添加可选x64或x86，修复class识别错误问题。
* 3.5 添加扫描仅需要系统环境dll的单文件exe，适用于patch。
* 3.6 添加扫描时候判断是否存在控制台，不想要黑窗口的伙伴可以更新，【-h】显示使用例子（默认仅显示参数），添加中英双译。

```
用法: ZeroEye [选项]
选项:
  -h    <帮助|例子>                             #显示帮助信息
  -i    <PE  文件>                              #列出Exe的导入表
  -p    <文件目录>                              #自动扫描指定目录下可疑的恶意程序
  -s    <签名校验>                              #只扫描有签名的exe程序
  -e    <排除 EXE>                              #排除系统系统dll和exe
  -d    <指定模块>                              #分析dll模块
  -x    <指定架构>                              #指定要扫描的架构（x86/x64）
  -g    <排除列表>                              #排除指定dll的扫描
  -IM   <PE  文件>                              #查看导入表
  -EX   <PE  文件>                              #查看导出表
  -nc   <排除控制台>                            #排除控制台应用程序
示例:
  ZeroEye.exe -i a.exe                                     #显示exe导入表
  ZeroEye.exe -p c:\                                       #扫描c盘下的exe
  ZeroEye.exe -d a.dll                                     #分析指定dll的导入模块
  ZeroEye.exe -IM/-EX a.exe/a.dll                          #查看导入表/导出表
  ZeroEye.exe -p c:\ -s -x 64 -g "api-ms|ucrtbase|crt"      #扫描c盘下的exe,并且只扫描64位有签名的程序
  ZeroEye.exe -p c:\ -s -x 64 -g "api-ms|ucrtbase|crt" -e   #同上，扫描仅需要系统dll的exe
  ZeroEye.exe -p c:\ -s -x 64 -g "api-ms|ucrtbase|crt" -nc  #同上，排除控制台应用程序
```
---

# 1.0 ~ 3.0版本不过多介绍

---
## 3.1版本
### 存在问题

* 修复遍历导入表时，遇到空格名称输出问题。
 
* 修复目录遍历功能，可正常遍历整个盘符。

* 修复dllname触发的0xc05的内存访问冲突报错。

* 整理代码，并且对部分做出调整。

---
## 3.2版本
### 存在问题

* 优先排序可劫持目录顺序，例如：可劫持的用户dll为1个，那么输出的目录名称为(1)、xxxx

* 禁用损坏镜像的信息提示。

* 优化Is_SystemDLL中的LoadLibraryA改为LoadLibraryExA，防止恶意dll被加载！！

---

## 3.3版本
### 添加功能及优化

* 优化代码，实现快速扫盘

* 查看64 or 86的导入导出表

* dll递归查询

* 签名校验
  
* 生成模板

---
## 3.4版本
### 添加功能及优化

* 修复class识别问题

* 添加功能,支持指定x64或x86

---
## 3.5版本
### 添加功能及优化

* 添加扫描功能：对只需要系统dll（不依赖其他dll）的exe进行筛选，方便用户进行patch免杀

* 该功能用法类似于扫白加黑，再末尾加【-e】参数即可！
---
## 3.6版本
### 添加功能及优化

* 添加扫描功能：判断程序是否有控制台黑窗口

* 修改之前的例子提示，该版本需要加【-h】显示使用实例

* 添加了中英双译

* 该功能用法类似于扫白加黑，再末尾加【-nc】参数即可！
---

## ⭐⭐Stargazers over time ⭐⭐
[![Stargazers over time](https://starchart.cc/ImCoriander/ZeroEye.svg?variant=adaptive)](https://starchart.cc/ImCoriander/ZeroEye)

