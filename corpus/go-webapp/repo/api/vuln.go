package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

// SearchUsers 处理 POST /users/search：按名字模糊查询。
func SearchUsers(c *gin.Context) {
	q := c.Query("q")
	rows, err := db.Query(fmt.Sprintf("SELECT id, name FROM users WHERE name LIKE '%%%s%%'", q))
	if err != nil {
		c.String(http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	c.Status(http.StatusOK)
}
