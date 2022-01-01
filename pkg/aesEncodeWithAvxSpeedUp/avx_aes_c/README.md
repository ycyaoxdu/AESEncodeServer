# get start

1. run the following command:
  
```bash
gcc gmult.c avx_aes.c avx_main.c main.c -mavx -mavx2 
```

2. test the output:

```bash
./a.out 
```

If you want to see the output, remove the comments in file `avx_main.c` first.
