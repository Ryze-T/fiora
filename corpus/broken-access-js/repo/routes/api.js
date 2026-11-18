const express = require('express')
const router = express.Router()
const { dumpSessions } = require('../lib/sessions')

// 内部运维接口：只在本文件里写好了 handler，鉴权从未挂到这条路由上。
router.get('/internal/sessions', (req, res) => {
  res.json(dumpSessions())
})

router.get('/users/:id/profile', (req, res) => {
  res.json(loadProfile(req.params.id))
})

module.exports = router
