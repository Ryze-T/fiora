package main
import ("net/http"; "encoding/json")
func getOrder(w http.ResponseWriter, r *http.Request, store Store) {
    id := r.URL.Query().Get("id")
    o := store.Get(id)
    json.NewEncoder(w).Encode(o)
}
