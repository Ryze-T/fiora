package main
import ("net/http"; "os/exec"; "strings")
func handler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    out, err := exec.Command("sh", "-c", "ping -c1 "+host).CombinedOutput()
    if err != nil { http.Error(w, err.Error(), 500); return }
    w.Write(out)
}
func main() { http.HandleFunc("/ping", handler); http.ListenAndServe(":8080", nil) }
