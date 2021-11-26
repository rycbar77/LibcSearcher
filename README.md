# Search libc function offset

## 简介

修改自[lieanu/LibcSearcher](https://github.com/lieanu/LibcSearcher) ，主要添加了在线查询接口

这是针对 CTF 比赛所做的小工具，在泄露了 Libc 中的某一个函数地址后，常常为不知道对方所使用的操作系统及 libc 的版本而苦恼，常规方法就是挨个把常见的 Libc.so 从系统里拿出来，与泄露的地址对比一下最后 12 位。

为了不在这一块浪费太多生命，写了几行代码，方便以后重用。

这里用了 [libc-database](https://github.com/niklasb/libc-database) 的数据库。

## 进度

- [x] 更新 libc-database
- [x] 在线查询接口

## 安装

```shell
# clone this repo
git clone --recursive https://github.com/rycbar77/LibcSearcher.git
cd LibcSearcher
python setup.py develop
# download libc file
cd libc-database
# see README for libc-database
./get
```

## 示例

```python
from LibcSearcher import *

# 本地查询
# 第二个参数，为已泄露的实际地址，或最后 12 位 (比如：d90)，int 类型
obj = LibcSearcher("fgets", 0X7ff39014bd90)

# 使用libc-database在线api查询
obj = LibcSearcher("fgets", 0X7ff39014bd90, online=True)

obj.dump("system")        #system 偏移
obj.dump("str_bin_sh")    #/bin/sh 偏移
obj.dump("__libc_start_main_ret")    
```

如果遇到返回多个 libc 版本库的情况，可以通过`add_condition(leaked_func, leaked_address)`来添加限制条件，也可以手工选择其中一个 libc 版本（如果你确定的话）。

## 其它

与原版的用法不变，兼容原先的脚本

默认使用本地查询，因为本地查询效率更高，且线下~~理论上~~会断网

在线查询会受到网络的影响，速度较慢且不稳定

欢迎提issue
