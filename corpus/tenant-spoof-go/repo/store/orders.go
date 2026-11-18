package store

import (
	"database/sql"
	"encoding/json"
)

// OrdersByTenant 按租户取订单：签名默认调用方传入的是可信租户身份。
func OrdersByTenant(tenant string) ([]json.RawMessage, error) {
	rows, err := db.Query("SELECT body FROM orders WHERE tenant_id = $1", tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var body json.RawMessage
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		out = append(out, body)
	}
	return out, nil
}

var db *sql.DB
