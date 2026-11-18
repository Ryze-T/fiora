import sqlite3
def login(conn, username, password):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + username + "' AND pass='" + password + "'")
    return cur.fetchone()
