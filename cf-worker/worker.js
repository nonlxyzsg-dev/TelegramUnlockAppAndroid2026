/**
 * Cloudflare Worker — WebSocket relay для Telegram MTProto.
 *
 * Маршрут: wss://your-worker.workers.dev/dc{1-5}/apiws
 *   → проксирует в wss://kws{N}.web.telegram.org/apiws
 *
 * ТСПУ видит TLS к Cloudflare (не к Telegram) — нет причин блокировать.
 */

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Парсим путь: /dc2/apiws → DC 2
    const match = url.pathname.match(/^\/dc(\d+)(\/.*)?$/);
    if (!match) {
      return new Response(
        'Telegram WS Relay v2\n\nИспользование: /dc{1-5}/apiws\nПример: wss://this-worker.workers.dev/dc2/apiws\n',
        { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }

    const dc = parseInt(match[1]);
    if (dc < 1 || dc > 5) {
      return new Response('DC must be 1-5', { status: 400 });
    }

    const path = match[2] || '/apiws';
    const targetHost = `kws${dc}.web.telegram.org`;
    const targetUrl = `https://${targetHost}${path}`;

    // Проверяем WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response(`Relay OK. Target: ${targetHost}`, { status: 200 });
    }

    // Простой прокси: Cloudflare автоматически проксирует WS при fetch с upgrade
    // Копируем необходимые заголовки
    const proxyHeaders = new Headers();
    proxyHeaders.set('Host', targetHost);
    proxyHeaders.set('Origin', 'https://web.telegram.org');
    proxyHeaders.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

    // Все WS заголовки
    for (const [key, val] of request.headers) {
      if (key.toLowerCase().startsWith('sec-websocket')) {
        proxyHeaders.set(key, val);
      }
    }
    proxyHeaders.set('Upgrade', 'websocket');
    proxyHeaders.set('Connection', 'Upgrade');

    // fetch с правильным upgrade — Cloudflare проксирует WS
    return fetch(targetUrl, {
      headers: proxyHeaders,
    });
  },
};
