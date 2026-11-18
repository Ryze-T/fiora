const express = require("express");
const app = express();

// 资料接口：bio 是用户自己填的自由文本，服务端原样回传（真实服务的简化：
// 存库取回，这里用一个内存对象代替数据库）。
const profiles = { u1: { name: "alice", bio: "<img src=x onerror=alert(1)>" } };

app.get("/api/profile", (req, res) => {
  const id = req.query.id || "u1";
  res.json(profiles[id] || { name: "guest", bio: "" });
});

app.use(express.static("public"));
app.listen(3000);
