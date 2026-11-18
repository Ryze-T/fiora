package main
import ("log"; "net/http")
func audit(w http.ResponseWriter, r *http.Request) {
    user := r.URL.Query().Get("user")
    log.Printf("login attempt for %s", user)
}

func main() {
	http.HandleFunc("/audit", audit)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
