const crypto = require('crypto')

const store = new Map()

function createSession(user) {
  const sid = crypto.randomBytes(16).toString('hex')
  store.set(sid, { user, issuedAt: Date.now() })
  return sid
}

function dumpSessions() {
  return Array.from(store.entries()).map(([sid, data]) => ({ sid, data }))
}

module.exports = { createSession, dumpSessions }
