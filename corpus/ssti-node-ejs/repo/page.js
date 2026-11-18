const ejs = require("ejs");
module.exports = (req, res) => {
  const html = ejs.render(req.body.template, { user: req.body.user });
  res.send(html);
};
