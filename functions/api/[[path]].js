addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const tg_host = "api.telegram.org";

async function handleRequest(request) {
  const u = new URL(request.url);
  u.host = tg_host;
  // 保留原始路径
  u.pathname = u.pathname;

  const req = new Request(u, {
    method: request.method,
    headers: request.headers,
    body: request.body
  });

  return fetch(req);
}
