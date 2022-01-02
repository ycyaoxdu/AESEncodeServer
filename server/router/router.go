package router

import (
	"encoding/base64"
	"fmt"
	"strings"

	aes "github.com/ycyaoxdu/AESEncodeServer/pkg/aesEncodeWithAvxSpeedUp"
	"github.com/ycyaoxdu/AESEncodeServer/server/model"

	"github.com/gin-gonic/gin"
)

func SetRouter(e *gin.Engine) {
	e.GET("/encode/*msg", EncodeHandler)
	e.GET("/decode/*msg", DecodeHandelr)
}

func EncodeHandler(ctx *gin.Context) {
	var msg model.Message

	if err := ctx.ShouldBindUri(&msg); err != nil {
		ctx.JSON(400, gin.H{"msg": err})
		return
	}
	str := strings.TrimPrefix(msg.Msg, "/")

	result := aes.Encode(str)

	res := model.Response{
		Msg: result,
	}

	ctx.JSON(200, gin.H{
		"message": res,
	})
}

func DecodeHandelr(ctx *gin.Context) {
	var msg model.Message

	if err := ctx.ShouldBindUri(&msg); err != nil {
		ctx.JSON(400, gin.H{"msg": err})
		return
	}
	str := strings.TrimPrefix(msg.Msg, "/")

	if !lengthCheck(str) {
		ctx.JSON(400, gin.H{
			"msg": "wrong input length! have you changed it?",
		})
		return
	}

	by, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println(err)
	}

	result := aes.Decode(string(by))

	res := model.Message{
		Msg: string(result),
	}

	ctx.JSON(200, gin.H{
		"message": res,
	})
}

// check length for base64 encode
func lengthCheck(s string) bool {
	if len(s)%4 != 0 {
		return false
	}
	rrLen := len(s) / 4

	if ((rrLen-1)*3%16) != 0 && ((rrLen*3)%16) != 0 {
		return false
	}
	return true
}
