const express = require('express')
const router = express.Router()
const { createSession } = require('../lib/sessions')

// 登录后会写进同一个 store——所以 /api/internal/sessions 泄的是真实会话。
router.post('/login', (req, res) => {
  const sid = createSession({ name: req.body.name, role: 'user' })
  res.cookie('sid', sid)
  res.json({ ok: true })
})

module.exports = router
