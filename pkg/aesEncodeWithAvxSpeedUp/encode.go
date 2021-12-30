package aesEncodeWithAvxSpeedUp

//#cgo CFLAGS: "-mavx" "-mavx2"
//#include "avx_aes_c/gmult.c"
//#include "avx_aes_c/avx_aes.c"
//#include "avx_aes_c/avx_main.c"
import "C"
import (
	"fmt"
	"reflect"
	"sort"
	"sync"
	"unsafe"
)

type message struct {
	data []byte
	id   int
}

func encode(msg []byte, waitgroup *sync.WaitGroup, buff chan<- message, i int) {

	d := (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	a := C.run(d)

	// reference https://github.com/golang/go/issues/13656#issuecomment-165867188
	sh := reflect.SliceHeader{uintptr(unsafe.Pointer(a)), 16, 32}
	out := *(*[]C.uint8_t)(unsafe.Pointer(&sh))
	var outslice []byte
	for _, d := range out {
		outslice = append(outslice, byte(d))
	}
	var temp message
	temp.data = outslice
	temp.id = i

	buff <- temp

	waitgroup.Done()
}

func Encode(input string) (res []byte) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("Panicing %s\r\n", err)
		}
	}()

	var rawResult []message

	wg := sync.WaitGroup{}
	channel := make(chan message, 10)

	padtext := PaddingByte([]byte(input))
	var data [][]byte

	for len(padtext) > 0 {
		if len(padtext)%16 != 0 {
			fmt.Errorf("wrong length!")
		}
		data = append(data, padtext[:16])
		padtext = padtext[16:]
	}

	for index, str128 := range data {
		wg.Add(1)
		go encode(str128, &wg, channel, index)
		fmt.Println("index:", index)
	}

	wg.Wait()
	close(channel)
	fmt.Println("channel closed")

	for aa := range channel {
		rawResult = append(rawResult, aa)
	}

	sort.Slice(rawResult, func(i, j int) bool {
		return rawResult[i].id < rawResult[j].id
	})

	for len(rawResult) > 0 {
		res = append(res, rawResult[0].data...)
		rawResult = rawResult[1:]
	}
	fmt.Println("function encode finished")

	return
}
