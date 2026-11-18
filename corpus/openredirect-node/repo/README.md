# openredirect-node

Express 处理器把 `req.query.next` 原样交给 `res.redirect`，未做同源/白名单校验。

入口链真实接线：`package.json` 的 `main`/`start` → `app.js` 把 `auth` 挂到
`/login/callback` → `auth.js` 的 `res.redirect(req.query.next)` 汇点。
