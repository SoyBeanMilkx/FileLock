# KernelMod
A linux(android) kernel module that prevents important files from being deleted

前两天手机有的文件被小孩误删了，一气之下写了这个模块

功能:保护用户输入目录的文件

模块启用后，目标文件无法读写，无法被删除，无法重命名，无法移动，无法复制

此项目仅供参考 可能存在一些bug，请勿乱刷内核模块😋😋😋
