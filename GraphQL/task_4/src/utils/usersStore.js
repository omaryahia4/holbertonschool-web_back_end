import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const storePath = path.join(__dirname, 'usersStore.json');

function ensureFile() {
  if (!fs.existsSync(storePath)) fs.writeFileSync(storePath, '[]', 'utf-8');
}

export function getAll() {
  ensureFile();
  const raw = fs.readFileSync(storePath, 'utf-8');
  try { return JSON.parse(raw); } catch { return []; }
}

export function saveAll(users) {
  fs.writeFileSync(storePath, JSON.stringify(users, null, 2), 'utf-8');
}

export function findByEmail(email) {
  return getAll().find(u => u.email === email) || null;
}

export function findById(id) {
  return getAll().find(u => u.id === id) || null;
}

export function add(user) {
  const users = getAll();
  users.push(user);
  saveAll(users);
  return user;
}
