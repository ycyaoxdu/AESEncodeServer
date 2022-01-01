package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	aes "github.com/ycyaoxdu/AESEncodeServer/pkg/aesEncode"
	// avxaes "github.com/ycyaoxdu/AESEncodeServer/pkg/aesEncodeWithAvxSpeedUp"
)

func main() {
	// server.RunServer()
	test()
}

func test() {
	f, err := os.Open("text.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {

		line := scanner.Text()
		fmt.Println("length", len(line))

		testAes(line)
		testParaAes(line)
		//
		// testAvxAes(line)
		// testParaAvxAes(line)
	}

}

// func testParaAvxAes(input string) {
// 	start := time.Now()

// 	_ = avxaes.Encode(input)

// 	period := time.Since(start)
// 	fmt.Println("para avx aes time cost: ", period)

// 	// fmt.Println(res)

// }

// func testAvxAes(input string) {
// 	start := time.Now()

// 	_ = avxaes.SerialEncode(input)

// 	period := time.Since(start)
// 	fmt.Println("avx aes time cost: ", period)

// 	// fmt.Println(res)
// }

//
func testParaAes(input string) {
	start := time.Now()

	_ = aes.Encode(input)

	period := time.Since(start)
	fmt.Println("para aes time cost: ", period)

	// fmt.Println(res)
}

func testAes(input string) {
	start := time.Now()

	_ = aes.SerialEncode(input)

	period := time.Since(start)
	fmt.Println("aes time cost: ", period)

	// fmt.Println(res)
}
