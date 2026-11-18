# xss-node-innerhtml

Node/DOM XSS：`public/view.js` 把服务端返回的 `bio` 直接写进 `innerHTML`。

入口链是真实接线的：`package.json` 的 `main`/`start` → `app.js` 的
`/api/profile`（回传用户自填的 `bio`）→ `public/index.html`（`#profile` 节点 +
`fetch("/api/profile").then(render)`）→ `view.js` 的 `innerHTML` 汇点。
