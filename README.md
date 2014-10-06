
MKBundleManager
===============

mono mkbundle unpacker and file replace tool.

###支持 mtouch mtouch-64 mtouch.exe mandroid.exe 解包

### 使用说明

#####1. 将插件文件 MKBundleManager.py 放入 IDA Pro 的 plugins 目录
#####2. 用IDA打开待分析文件，等待分析完毕(左下角状态栏的 AU: idel)
#####3. IDA 菜单栏 点击 View -> Open subviews -> Bundled Assembly Manager
#####4. 在 Bundled Assembly Manager 窗口中可见程序集列表
#####5. 选择要修改的文件用右键菜单内 导出全部文件 或者 导出文件 命令导出到指定位置
#####6. 文件修改完毕后用右键菜单内 替换文件 命令 替换修改后的文件
#####7. 会在位于原程序所在目录内用原文件名+日期时间命名生成替换后的打包文件

### 注意

#####1. 可能会存在问题，请看IDA的输出窗口获取详细出错信息
#####2. .Net 程序集的修改可用 替换文件Radate .NET Reflector + Reflexil 插件
#####3. 当修改后的文件被压缩后大于原始文件的压缩数据大小时无法替换，这时，请用Reflexil删除修改后的程序集的冗余IL指令，减少程序集大小

