import sqlite3
# 真实 CVE 模式：用户输入经中转变量流入 execute（二次赋值注入）
def search(conn, request):
    kw = request.args.get("q")
    tmp = kw
    sql = "SELECT * FROM t WHERE k='" + tmp + "'"
    conn.execute(sql)
