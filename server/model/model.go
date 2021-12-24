package model

type Message struct {
	Msg string `uri:"msg" binding:"required"`
}
