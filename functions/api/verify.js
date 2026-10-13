/* ============================================================
   POST /api/verify  ——  进站闸门的服务端 siteverify
   ------------------------------------------------------------
   浏览器把 Turnstile 令牌发过来，这里用 Secret Key 向 Cloudflare 校验；
   校验只在服务端进行，Secret 永远不下发到前端。这是 Turnstile
   被认定为「已完整集成」的必要环节（仅前端渲染不作数）。

   环境变量：TURNSTILE_SECRET（Secret 类型）
            TURNSTILE_HOSTNAMES（可选，逗号分隔的前端域名白名单）
   ============================================================ */
function json(data, status){
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'}
  });
}

export async function onRequestPost({env, request}){
  const secret = env.TURNSTILE_SECRET || '';
  if (!secret) return json({ok: false, error: 'server not configured'}, 500);

  let body = {};
  try{ body = await request.json(); }catch(e){}
  const token = String(body.token || '');
  if (!token || token.length > 2048) return json({ok: false, error: 'bad token'}, 400);

  const ip = request.headers.get('CF-Connecting-IP') || '';
  let result;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({secret, response: token, remoteip: ip})
    });
    if (!r.ok) return json({ok: false, error: 'siteverify ' + r.status}, 502);
    result = await r.json();
  } catch (e) {
    return json({ok: false, error: 'siteverify error'}, 502);
  }

  /* 可选：限制只接受来自指定前端域名的验证结果 */
  const hosts = String(env.TURNSTILE_HOSTNAMES || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (hosts.length && (!result.hostname || !hosts.includes(result.hostname))) {
    return json({ok: false, error: 'hostname mismatch'}, 403);
  }

  if (!result.success) return json({ok: false, error: 'verification failed'}, 403);
  return json({ok: true});
}

export function onRequest(){
  return json({ok: false, error: 'method not allowed'}, 405);
}
