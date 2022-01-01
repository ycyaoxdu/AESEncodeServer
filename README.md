# get start

#### prerequiest

make sure you're using a CPU of x86 arch.

## run

```sh
$ go build -a -o app .
$ ./app 
```

## 测试数据说明

使用以上指令分别对使用avx、不使用avx的实现进行重复编译、执行并保存记录三次，结果存储于`time_cost_record`文件夹下。

`test*.txt`是将`test_avx*.txt`与`test_non_avx*.txt`中的原始数据进行了整合。
