const express = require('express')
const router = express.Router()

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' })
  }
  next()
}

router.use(requireAdmin)
router.get('/users', (req, res) => res.json(listAllUsers()))

module.exports = router
