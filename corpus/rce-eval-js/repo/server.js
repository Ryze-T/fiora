const express = require("express");
const app = express();
app.post("/calc", (req, res) => {
  const expr = req.body.expr;
  const result = eval(expr);
  res.json({ result });
});
app.listen(3000);
