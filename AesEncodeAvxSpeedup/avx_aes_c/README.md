# get start
1. add main function
2. run the following command:
*add a main.c newfile with a main funciton to call the funciton in avx_main.c*   
```bash
gcc gmult.c avx_aes.c avx_main.c main.c -mavx -mavx2 
```
3. test the output:
```bash
./a.out
```

