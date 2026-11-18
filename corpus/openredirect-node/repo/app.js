const express = require("express");
const auth = require("./auth");
const app = express();

// 登录后的跳转入口：next 由调用方给出（真实服务的简化：登录成功页回跳）。
app.get("/login/callback", auth);

app.listen(3000);
