package main
import ("net/http"; "os"; "io")
func download(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    f, err := os.Open("data/" + name)
    if err != nil { http.NotFound(w, r); return }
    defer f.Close()
    io.Copy(w, f)
}
