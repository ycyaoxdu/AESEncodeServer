# get start

#### prerequiest

make sure you're using a CPU of x86 arch.

## run

Have a try.

```bash
$ go run main.go
```

Or you want to build a binary,then run:

```sh
$ go build -a -o app .
$ ./app
```

## api

```
GET http://localhost:8086/encode/<your message>
GET http://localhost:8086/decode/<your message>
```
