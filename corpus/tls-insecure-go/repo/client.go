package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// insecureClient 跳过证书校验（对接自签内网网关时的临时方案，一直没改回来）。
func insecureClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// healthcheck 拉取上游网关健康状态，供 cron 每分钟调用。
func healthcheck(url string) int {
	resp, err := insecureClient().Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck failed:", err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return 0
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: healthcheck <url>")
		os.Exit(2)
	}
	os.Exit(healthcheck(os.Args[1]))
}
