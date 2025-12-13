const bcrypt = require('bcryptjs');
const db = require('./db');

const sanitizeUser = (user) => user
  ? { id: user.id, username: user.username, role: user.role }
  : null;

const verifyCredentials = (username, password) => {
  const user = db.getUserByUsername(username);
  if (!user) return null;

  const isValid = bcrypt.compareSync(password, user.password_hash);
  if (!isValid) return null;

  return user;
};

const requireAuth = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ error: 'Auth required.' });
  }
  return next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ error: 'Auth required.' });
  }
  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only.' });
  }
  return next();
};

module.exports = {
  sanitizeUser,
  verifyCredentials,
  requireAuth,
  requireAdmin,
};

