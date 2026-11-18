const express = require('express')
const apiRouter = require('./routes/api')
const adminRouter = require('./routes/admin')
const loginRouter = require('./routes/login')

const app = express()

// 管理后台挂了鉴权中间件……
app.use('/admin', adminRouter)
// ……但 /api 挂载时没有任何鉴权，而 api 里包含内部运维接口。
app.use('/api', apiRouter)
// 登录路由写入会话，因此 /api/internal/sessions 泄漏的是真实会话
app.use('/login', loginRouter)

app.listen(3000)
