# KernelMod
A Linux (Android) kernel module based on kernelpatch that prevents important files or partitions from being deleted or written to

基于 kernelpatch 的 linux(android) 内核模块，可防止重要文件或者分区被删除或写入

此项目基于[FileLock](https://github.com/SoyBeanMilkx/FileLock)

由于原项目适配起来比较麻烦，干脆就直接重构了

# 前言
1.此模块仅作为参考使用，并不能保证百分百适配，可能对你的设备没有任何保护作用，请自行测试

2.旧版linux内核与新版linux内核部分函数名称不一致,可能会导致hook不到指定函数,导致保护失败

3.请自行查看dmesg日志判断是否hook成功

# 功能介绍
1.保护用户输入的  目录  文件夹  文件

2.模块启用后，目标文件无法写，无法被删除，无法重命名，你几乎完全无法操作这个文件

3.如果你要让文件变得“几乎完全无法操作”（无法读写，无法被删除，无法重命名，无法移动，无法复制），那就自己改代码吧，代码里留了示例。

# 使用方法
add 【示例:add /data/media/0/mod_main.kpm】保护这个地址
****
remove 【示例:remove /data/media/0/mod_main.kpm】不再保护这个地址
****
rm -rf 【示例:rm -rf】保护提前在模块里预设的地址(不要问为什么是rm，问就是😋😋😋)
****
unhook【示例:unhook】卸载/还原?已hook的函数
****
ls【示例:ls】在dmesg日志中打印并列出已保护的地址


# 此项目仅供参考 可能存在一些bug,请勿乱刷内核模块😋😋😋
