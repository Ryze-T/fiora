const express = require("express");
const app = express();
app.get("/admin/export", (req, res) => {
  res.json(require("./db").dumpAll());
});
app.use(require("./auth-middleware"));
