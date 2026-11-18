package api

import (
	"encoding/json"
	"net/http"

	"example.com/shop/store"
)

// GET /orders?tenant=...：租户身份来自请求头，而会话里其实已经有 user.TenantID。
func OrderList(w http.ResponseWriter, r *http.Request) {
	user := CurrentUser(r)
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// 攻击者改一个请求头就能跨租户读数据；正确的取值应是 user.TenantID。
	tenant := r.Header.Get("X-Tenant-Id")
	rows, err := store.OrdersByTenant(tenant)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(rows)
}
