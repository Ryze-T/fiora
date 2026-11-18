package main
import ("os/exec"; "net/http")
// 真实 CVE 模式：参数经 Cmd.Args 字段注入（pattern 规则的盲区形态）
func advHandler(w http.ResponseWriter, r *http.Request) {
    arg := r.URL.Query().Get("a")
    c := exec.Command("tool")
    c.Args = append(c.Args, arg)
    c.Run()
}
