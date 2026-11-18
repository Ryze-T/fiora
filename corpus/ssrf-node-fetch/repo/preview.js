const express = require("express");
const axios = require("axios");
const app = express();
app.post("/preview", async (req, res) => {
  const r = await axios.get(req.body.url);
  res.send(r.data);
});
