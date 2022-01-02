# get start

#### prerequiest

make sure you're using a CPU of x86 arch.

## run

```sh
$ go build -a -o app .
$ ./app 
```

## 测试数据说明

`text.txt`内是原始输入数据。

使用以上指令分别对使用avx、不使用avx的实现进行重复编译、执行并保存记录，结果存储于`.txt`文件内。

