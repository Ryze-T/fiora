package api

import "net/http"

func ProxyFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, _ := http.Get(target)
	w.Write(resp.Body)
}
