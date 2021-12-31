package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	aes "github.com/ycyaoxdu/AESEncodeServer/pkg/aesEncodeWithAvxSpeedUp"
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
		fmt.Println(line)
		testParaAvxAes(line)

	}
}

func testParaAvxAes(input string) {
	start := time.Now()

	res := aes.Encode(input)

	period := time.Since(start)
	fmt.Println("para avx aes time cost: ", period)

	fmt.Println(res)

}
