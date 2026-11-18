const express = require("express");
const path = require("path");
const app = express();
app.get("/download", (req, res) => {
  res.sendFile(path.join("/uploads", req.query.name));
});
