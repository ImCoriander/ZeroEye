# ZeroEye

### 用于扫描 EXE 文件的导入表，列出导入的DLL文件，并筛选出非系统DLL，符合条件的文件将被复制到特定的 **binX64** 或 **binX86** 文件夹，并生成 **Infos.txt** 文件记录DLL信息。自动化找白文件，灰梭子好搭档！！！
    
### 灰梭子:快速对dll进行解析函数名，并且生成对应的劫持代码，实现快速利用vs进行编译，在下方公众号中也提供了劫持模板，可前往获取。

### ⭐确定不来一个吗？

### 更多关于本项目的介绍，请前往公众号：**[零攻防](https://mp.weixin.qq.com/s?__biz=MzkyNDUzNjk4MQ==&mid=2247484591&idx=1&sn=50b813e4c626aa967d6c506c4749c032&chksm=c1d51d55f6a294434e27bbcd6dc45268e64ac8a86bc1215c2df9140d350ea2f26ed6d91a2655#rd)**


# 版本介绍：

1.0~2.0版本可在Release中获取，将不再在以上基础上更新，以后将完全使用c++完成所有操作！！！

## 1.0版本
存在不足：复制不全,exe路径下，不存在dll！

## 2.0版本
更新：将exe路径下，只有exe和info两个文件进行剔除，只保留文件夹下存在多个文件的情况！

| 项目名          | 备注                                                         |
| --------------- | ------------------------------------------------------------ |
| x64/ZeroEye.exe | 检测x64白进程                                                |
| x86/ZeroEye.exe | 检测x86白进程                                                |
| Find_All.py     | 自动调用以上项目，实现自动遍历系统所有exe，将exe和dll自动放到当前路径的bin文件夹中。 |



---
# 3.0版本
| 项目名             | 备注       |
| --------------- | -------- |
| x64/ZeroEye.exe | 检测x64白进程 |
| x86/ZeroEye.exe | 检测x86白进程 |

```
Usage: ZeroEye [options]
    -h     帮助
    -i    <Exe 路径>    列出Exe的导入表
    -p    <文件路径>    自动搜索文件路径下可劫持利用的白名单

example：
ZeroEye.exe -p c:\             //搜索c盘所有exe是否有劫持的可能
ZeroEye.exe -i aaa.exe         //判断指定exe是否有劫持的可能
```

    
![image](https://github.com/user-attachments/assets/12ac33d7-aacb-477f-b119-51f6fa7c0730)

![image](https://github.com/user-attachments/assets/4ae352c5-5664-4654-be1c-ad005e823f71)

