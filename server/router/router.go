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

	if len(str)%16 != 0 {
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

	if len(by)%16 != 0 {
		ctx.JSON(400, gin.H{
			"msg": "wrong input length! have you changed it?",
		})
		return
	}

	res := model.Message{
		Msg: string(result),
	}

	ctx.JSON(200, gin.H{
		"message": res,
	})
}
