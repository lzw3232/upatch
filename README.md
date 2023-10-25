# upatch: dynamic user patching
# 用户态热补丁


1. 使用```redis-6.2.5```，```make -j8 MALLOC=libc```编译一个```redis-server```作为```debug-info```
2. 制作热补丁，upatch-build、upatch-diff、compiler-hijacker、as-hijacker在同一目录
```
sudo ./release/upatch-build 
-s ${redis根目录}
-i ${debug-info路径}
-b "make -j8 MALLOC=libc" 
-e ./src/redis-server
./test/redis/0001-Prevent-unauthenticated-client-from-easily-consuming.patch 
```
3. 启动redis-server
```
redis-server ./test/redis/resis.config
```
4. 测试

```
telnet 127.0.0.1 6380
*100
```
5. 使用upatch-manage打热补丁
```
upatch-manage patch -p ${运行的pid} -u ${热补丁} -b ${运行的redis-server二进制文件}
```
6. 测试

```
telnet 127.0.0.1 6380
*100