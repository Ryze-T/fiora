package main
import ("net/http"; "io")
func deliver(w http.ResponseWriter, r *http.Request) {
    target := r.FormValue("target")
    resp, err := http.Get(target)
    if err != nil { http.Error(w, err.Error(), 502); return }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
