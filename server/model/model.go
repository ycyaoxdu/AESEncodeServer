package model

type Message struct {
	Msg string `uri:"msg" binding:"required"`
}

type Response struct {
	Msg []byte `uri:"msg"`
}
