/* ============================================================
   POST /api/gh  ——  GitHub Contents API 代理（Cloudflare Pages Functions）
   ------------------------------------------------------------
   浏览器只带会话凭证（X-Admin-Token），真正的 GitHub Token 存在 Worker 的
   加密环境变量里，绝不下发给前端。会话有效才放行；仓库固定在服务端配置，
   客户端无法把 Token 指向别的仓库。

   需要的环境变量：
     GITHUB_TOKEN   具有 Contents: Read and write 权限的 Personal Access Token（Secret）
     GH_REPO        例如 HiEq/HOME
     SESSION_SECRET 与 /api/login 一致
     ADMIN_PASSWORD 与 /api/login 一致（会话签名的兜底密钥）
   ============================================================ */
const enc = new TextEncoder();

function b64urlDecode(s){
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function json(data, status){
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'}
  });
}
async function signSession(payload, secret){
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(payload)));
  let s = '';
  for (const b of sig) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function sigEqual(a, b){
  const x = b64urlDecode(a), y = b64urlDecode(b);
  if (x.length !== y.length || x.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
async function verifySession(token, env){
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return false;
  const exp = Number(parts[0]) || 0;
  if (!exp || exp < Date.now()) return false;                     /* 过期 */
  const payload = parts[0] + '.' + parts[1];
  const sig = await signSession(payload, env.SESSION_SECRET || env.ADMIN_PASSWORD || '');
  return sigEqual(sig, parts[2]);
}

export async function onRequestPost({env, request}){
  const token = request.headers.get('X-Admin-Token') || '';
  if (!(await verifySession(token, env))) return json({ok: false, error: 'unauthorized'}, 401);

  let body = {};
  try{ body = await request.json(); }catch(e){}
  const method = String(body.method || 'GET').toUpperCase();
  /* 空路径 = 仓库根目录（「测试连接」查的就是根目录），两侧多余斜杠先去掉 */
  const path = String(body.path || '').replace(/^\/+/, '').replace(/\/+$/, '');
  const repo = env.GH_REPO || '';
  /* 路径白名单校验：只允许普通字符、禁止 .. 路径穿越 */
  if (!repo || (path && (!/^[A-Za-z0-9._\-\/]+$/.test(path) || path.indexOf('..') >= 0))) {
    return json({ok: false, error: 'bad request'}, 400);
  }
  if (!['GET', 'PUT', 'DELETE'].includes(method)) return json({ok: false, error: 'bad method'}, 400);

  const url = 'https://api.github.com/repos/' + repo + '/contents/' + path.split('/').filter(Boolean).map(encodeURIComponent).join('/');

  /* ---------- 批量模式：多文件一次提交（Git Data API） ----------
     一次上传的 原图 + 缩略图 + gallery.json 合成同一个 commit，
     只触发一次 Cloudflare 部署，且清单与图片始终同时生效 */
  if (body.op === 'commit') {
    const files = Array.isArray(body.files) ? body.files : [];
    if (!files.length || files.length > 30) return json({ok: false, error: 'bad files'}, 400);
    for (const f of files) {
      const p = String(f && f.path || '');
      if (!p || !/^[A-Za-z0-9._\-\/]+$/.test(p) || p.indexOf('..') >= 0) return json({ok: false, error: 'bad path'}, 400);
    }
    const branch = /^[A-Za-z0-9._\-\/]+$/.test(String(body.branch || '')) ? String(body.branch) : 'main';
    const api = 'https://api.github.com/repos/' + repo;
    const H = {
      'Authorization': 'token ' + (env.GITHUB_TOKEN || ''),
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'hieq-home-pages',
      'Content-Type': 'application/json'
    };
    try {
      const ref = await (await fetch(api + '/git/ref/heads/' + branch, {headers: H})).json();
      const head = ref && ref.object && ref.object.sha;
      if (!head) return json({ok: false, error: 'no branch head'}, 502);
      const headCommit = await (await fetch(api + '/git/commits/' + head, {headers: H})).json();
      const baseTree = headCommit && headCommit.tree && headCommit.tree.sha;
      if (!baseTree) return json({ok: false, error: 'no base tree'}, 502);
      const tree = [];
      for (const f of files) {
        const blob = await (await fetch(api + '/git/blobs', {method: 'POST', headers: H, body: JSON.stringify({content: f.content, encoding: 'base64'})})).json();
        if (!blob || !blob.sha) return json({ok: false, error: 'blob failed'}, 502);
        tree.push({path: String(f.path), mode: '100644', type: 'blob', sha: blob.sha});
      }
      const newTree = await (await fetch(api + '/git/trees', {method: 'POST', headers: H, body: JSON.stringify({base_tree: baseTree, tree})})).json();
      if (!newTree || !newTree.sha) return json({ok: false, error: 'tree failed'}, 502);
      const commit = await (await fetch(api + '/git/commits', {method: 'POST', headers: H, body: JSON.stringify({message: String(body.message || 'update content'), tree: newTree.sha, parents: [head]})})).json();
      if (!commit || !commit.sha) return json({ok: false, error: 'commit failed'}, 502);
      await fetch(api + '/git/refs/heads/' + branch, {method: 'PATCH', headers: H, body: JSON.stringify({sha: commit.sha})});
      return json({ok: true, sha: commit.sha, files: files.length});
    } catch (e) {
      return json({ok: false, error: 'upstream error'}, 502);
    }
  }

  try {
    const res = await fetch(url, {
      method,
      headers: {
        'Authorization': 'token ' + (env.GITHUB_TOKEN || ''),
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'hieq-home-pages'
      },
      body: body.body ? String(body.body) : undefined
    });
    const data = await res.json().catch(() => null);
    return json(data, res.status);
  } catch (e) {
    return json({ok: false, error: 'upstream error'}, 502);
  }
}

export function onRequest(){
  return json({ok: false, error: 'method not allowed'}, 405);
}
