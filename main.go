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

/**
 *
 * !!!!!	此分枝仅用于速度测试比较
 *
 *
 * *	为验证速度，统一将所有输入取为16倍数，且对加密、解密算法给予相同输入，抛弃了结果，只关注计算速度。
 *
 * !	请将以下函数分为两组分别测试，测试一组时注释另一组。
 *
 */

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
		// testInvAes(line)
		//
		testParaAes(line)
		// testParaInvAes(line)

		// //
		// testAvxAes(line)
		// // testAvxInvAes(line)
		// //
		// testParaAvxAes(line)
		// // testParaAvxInvAes(line)
	}

}

/**
 *
 * * non-avx
 *
 */

func testAes(input string) {
	start := time.Now()

	_ = aes.SerialEncode(input)

	period := time.Since(start)
	fmt.Println("aes time cost: ", period)

	// fmt.Println(res)
}

//
func testInvAes(input string) {
	start := time.Now()

	_ = aes.SerialDecode(input)

	period := time.Since(start)
	fmt.Println("inv aes time cost: ", period)

	// fmt.Println(res)
}

//
func testParaAes(input string) {
	start := time.Now()

	_ = aes.Encode(input)

	period := time.Since(start)
	fmt.Println("para aes time cost: ", period)

	// fmt.Println(res)
}

func testParaInvAes(input string) {
	start := time.Now()

	_ = aes.Decode(input)

	period := time.Since(start)
	fmt.Println("para inv aes time cost: ", period)

	// fmt.Println(res)
}

/**
 *
 *
 * * 	avx
 *
 */

// func testAvxAes(input string) {
// 	start := time.Now()

// 	_ = avxaes.SerialEncode(input)

// 	period := time.Since(start)
// 	fmt.Println("avx aes time cost: ", period)

// 	// fmt.Println(res)
// }

// //
// func testAvxInvAes(input string) {
// 	start := time.Now()

// 	_ = avxaes.SerialDecode(input)

// 	period := time.Since(start)
// 	fmt.Println("avx inv aes time cost: ", period)

// 	// fmt.Println(res)
// }

// //
// func testParaAvxAes(input string) {
// 	start := time.Now()

// 	_ = avxaes.Encode(input)

// 	period := time.Since(start)
// 	fmt.Println("para avx aes time cost: ", period)

// 	// fmt.Println(res)

// }

// //
// func testParaAvxInvAes(input string) {
// 	start := time.Now()

// 	_ = avxaes.Decode(input)

// 	period := time.Since(start)
// 	fmt.Println("para avx inv aes time cost: ", period)

// 	// fmt.Println(res)

// }
