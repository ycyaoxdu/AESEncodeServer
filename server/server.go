package server

import (
	"github.com/ycyaoxdu/AESEncodeServer/server/router"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func RunServer() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: true,
	}))

	router.SetRouter(r)
	r.Run(":8086") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
