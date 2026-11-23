'use strict';
// 올스타 타워 디펜스 HQ - 계정/세이브 서버 (외부 패키지 없음, Node 16+)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';      // 리버스 프록시(nginx 등) 뒤라면 1
const MAX_BODY = 2 * 1024 * 1024;                          // 요청 본문 최대 2MB
const SESSION_MS = 30 * 24 * 3600 * 1000;                  // 로그인 유지 30일
const NAME_RE = /^[A-Za-z0-9가-힣_]{2,12}$/;

// ---------- 저장소 (JSON 파일, 원자적 쓰기) ----------
let db = { users: {}, sessions: {} };
try {
  db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  db.users = db.users || {}; db.sessions = db.sessions || {};
} catch (e) { /* 첫 실행 */ }

let dirty = false, writing = false;
function flush() {
  if (!dirty || writing) return;
  dirty = false; writing = true;
  const tmp = DATA_FILE + '.tmp';
  fs.writeFile(tmp, JSON.stringify(db), err => {
    if (err) { writing = false; dirty = true; console.error('save error', err); return; }
    fs.rename(tmp, DATA_FILE, e => {
      writing = false;
      if (e) { dirty = true; console.error('rename error', e); }
      if (dirty) flush();
    });
  });
}
const markDirty = () => { dirty = true; };
setInterval(flush, 2000);
function flushSync() { try { fs.writeFileSync(DATA_FILE, JSON.stringify(db)); } catch (e) { console.error(e); } }
['SIGINT', 'SIGTERM'].forEach(s => process.on(s, () => { flushSync(); process.exit(0); }));

// 키 앞에 접두어를 붙여 "__proto__" 같은 이름으로 인한 문제 방지
const ukey = name => 'u_' + name;
const sha = t => crypto.createHash('sha256').update(t).digest('hex');

// ---------- 비밀번호 ----------
function hashPw(pw, salt) {
  return new Promise((res, rej) => crypto.scrypt(pw, salt, 32, (e, k) => e ? rej(e) : res(k.toString('hex'))));
}
async function verifyPw(pw, user) {
  const h = await hashPw(pw, user.salt);
  const a = Buffer.from(h, 'hex'), b = Buffer.from(user.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- 로그인 시도 제한 (IP당 10분에 실패 10회) ----------
const fails = new Map();
function ipOf(req) {
  if (TRUST_PROXY) { const x = req.headers['x-forwarded-for']; if (x) return String(x).split(',')[0].trim(); }
  return req.socket.remoteAddress || '?';
}
function blocked(ip) { const f = fails.get(ip); return !!f && f.n >= 10 && Date.now() - f.t < 600000; }
function addFail(ip) {
  const f = fails.get(ip);
  if (!f || Date.now() - f.t >= 600000) fails.set(ip, { n: 1, t: Date.now() }); else f.n++;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of fails) if (now - v.t >= 600000) fails.delete(k); }, 60000);

// ---------- 세션 ----------
function newSession(name) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { name, exp: Date.now() + SESSION_MS };
  markDirty();
  return token;
}
function authOf(req) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || '');
  if (!m) return null;
  const s = db.sessions[sha(m[1])];
  if (!s || s.exp < Date.now()) return null;
  return s.name;
}
setInterval(() => {
  const now = Date.now(); let ch = false;
  for (const k of Object.keys(db.sessions)) if (db.sessions[k].exp < now) { delete db.sessions[k]; ch = true; }
  if (ch) markDirty();
}, 3600000);

// ---------- 유틸 ----------
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('too large'), { code: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { reject(Object.assign(e, { code: 400 })); } });
    req.on('error', reject);
  });
}
const isObj = o => o && typeof o === 'object' && !Array.isArray(o);

// ---------- 라우터 ----------
const INDEX = path.join(__dirname, 'public', 'index.html');
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  res.setHeader('X-Content-Type-Options', 'nosniff');
  try {
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      fs.readFile(INDEX, (e, buf) => {
        if (e) { res.writeHead(500); res.end('index.html 없음 (public/ 폴더 확인)'); return; }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
        res.end(buf);
      });
      return;
    }
    if (req.method === 'GET' && url === '/healthz') return send(res, 200, { ok: true });

    // 로그인 / 자동 가입
    if (req.method === 'POST' && url === '/api/auth') {
      const ip = ipOf(req);
      if (blocked(ip)) return send(res, 429, { error: '시도가 너무 많습니다. 10분 뒤에 다시 시도하세요' });
      const b = await readJson(req);
      const name = String(b.name || '').trim(), pw = String(b.pw || '');
      if (!NAME_RE.test(name) || pw.length < 3 || pw.length > 100)
        return send(res, 400, { error: '이름 2~12자(한글/영문/숫자), 비밀번호 3자 이상' });
      const k = ukey(name), u = db.users[k];
      if (!u) {
        if (!isObj(b.init)) return send(res, 400, { error: '초기 데이터가 없습니다' });
        const salt = crypto.randomBytes(16).toString('hex');
        db.users[k] = { name, salt, hash: await hashPw(pw, salt), data: b.init, created: Date.now() };
        markDirty();
        return send(res, 200, { token: newSession(name), data: db.users[k].data, isNew: true });
      }
      if (!(await verifyPw(pw, u))) { addFail(ip); return send(res, 401, { error: '비밀번호가 틀렸습니다' }); }
      fails.delete(ip);
      return send(res, 200, { token: newSession(name), data: u.data, isNew: false });
    }

    // 세이브 불러오기 / 저장
    if (url === '/api/load' && req.method === 'GET') {
      const name = authOf(req); if (!name) return send(res, 401, { error: '로그인이 필요합니다' });
      return send(res, 200, { data: db.users[ukey(name)].data });
    }
    if (url === '/api/save' && req.method === 'POST') {
      const name = authOf(req); if (!name) return send(res, 401, { error: '로그인이 필요합니다' });
      const b = await readJson(req);
      if (!isObj(b.data) || !Array.isArray(b.data.inv)) return send(res, 400, { error: '잘못된 세이브 데이터' });
      db.users[ukey(name)].data = b.data; markDirty();
      return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'not found' });
  } catch (e) {
    if (e && (e.code === 413 || e.code === 400)) return send(res, e.code, { error: e.code === 413 ? '데이터가 너무 큽니다' : '잘못된 요청' });
    console.error(e); send(res, 500, { error: '서버 오류' });
  }
});
server.listen(PORT, () => console.log(`서버 실행: http://localhost:${PORT}`));
