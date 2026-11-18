package main
import ("net/http")
func h(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Location", r.URL.Query().Get("to"))
    w.WriteHeader(302)
}
