package api

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

// Setup 挂载全部业务路由。
func Setup(r *gin.Engine, database *sql.DB) {
	db = database
	r.GET("/users/:id", GetUser)
	r.POST("/login", Login)
	r.POST("/proxy", ProxyFetch)
	r.POST("/users/search", SearchUsers)
}
