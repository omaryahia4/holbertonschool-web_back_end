import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { findByEmail as findUserByEmail } from '../utils/usersStore.js';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES_IN = '1h';

export function createToken(user) {
  const payload = { sub: user.id, role: user.role, email: user.email };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

export async function authenticate(email, password) {
  const user = findUserByEmail(email);
  if (!user) return null;
  if (user.passwordHash) {
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return null;
    return user;
  }
  if (user.password && user.password === password) return user;
  return null;
}

export function requireAuth(context) {
  if (!context.user) {
    const err = new Error('Authentication required');
    err.extensions = { code: 'UNAUTHENTICATED' };
    throw err;
  }
}

export function requireRole(context, role) {
  requireAuth(context);
  if (context.user.role !== role) {
    const err = new Error('Forbidden');
    err.extensions = { code: 'FORBIDDEN' };
    throw err;
  }
}
