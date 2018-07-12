# libsecurity

## Android编译

cd android执行sh build.sh

## iOS编译

打开iOS目录下的project文件然后build即可

## linux / macos java so

```
//g++ -fPIC -shared -c aes_core.cpp base64.cpp md5.cpp security.cpp -I /Library/Java/JavaVirtualMachines/jdk1.8.0_144.jdk/Contents/Home/include -I /Library/Java/JavaVirtualMachines/jdk1.8.0_144.jdk/Contents/Home/include/darwin 
//g++ -fPIC -shared -o libsecurity.so aes_core.o base64.o md5.o security.o
```