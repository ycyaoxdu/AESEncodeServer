package router

import (
	aes "ycyaoxdu/AESEncodeServer/pkg/aesEncodeWithAvxSpeedUp"
	"ycyaoxdu/AESEncodeServer/server/model"

	"github.com/gin-gonic/gin"
)

func SetRouter(e *gin.Engine) {
	e.GET("/encode/:msg", EncodeHandler)
	e.GET("/decode/:msg", DecodeHandelr)
}

func EncodeHandler(ctx *gin.Context) {
	var msg model.Message

	if err := ctx.ShouldBindUri(&msg); err != nil {
		ctx.JSON(400, gin.H{"msg": err})
		return
	}
	res := aes.Encode(msg.Msg)

	ctx.JSON(200, gin.H{
		"message": string(res),
	})
}

func DecodeHandelr(ctx *gin.Context) {
	var msg model.Message

	if err := ctx.ShouldBindUri(&msg); err != nil {
		ctx.JSON(400, gin.H{"msg": err})
		return
	}
	ctx.JSON(200, gin.H{
		"message": msg.Msg,
	})
}
