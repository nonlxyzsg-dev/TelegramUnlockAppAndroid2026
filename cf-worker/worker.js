/**
 * Cloudflare Worker — WebSocket relay для Telegram MTProto.
 *
 * Маршрут: wss://your-worker.workers.dev/dc{1-5}/apiws
 *   → проксирует в wss://kws{N}.web.telegram.org/apiws
 *
 * ТСПУ видит TLS к Cloudflare (не к Telegram) — нет причин блокировать.
 *
 * Деплой:
 *   1. Зарегистрируйтесь на https://dash.cloudflare.com
 *   2. Workers & Pages → Create Worker
 *   3. Вставьте этот код → Deploy
 *   4. В приложении укажите Relay URL: https://your-worker.workers.dev
 */

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Парсим путь: /dc2/apiws → DC 2
    const match = url.pathname.match(/^\/dc(\d+)(\/.*)?$/);
    if (!match) {
      return new Response(
        'Telegram WS Relay\n\nИспользование: /dc{1-5}/apiws\nПример: wss://this-worker.workers.dev/dc2/apiws\n',
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
      return new Response('WebSocket upgrade required', { status: 426 });
    }

    // Проксируем WebSocket в Telegram
    // Cloudflare автоматически обрабатывает WS-проксирование при fetch с Upgrade
    const newHeaders = new Headers();
    newHeaders.set('Host', targetHost);
    newHeaders.set('Upgrade', 'websocket');
    newHeaders.set('Connection', 'Upgrade');

    // Копируем WS-заголовки
    for (const key of ['Sec-WebSocket-Key', 'Sec-WebSocket-Version', 'Sec-WebSocket-Protocol']) {
      const val = request.headers.get(key);
      if (val) newHeaders.set(key, val);
    }

    // User-Agent как у браузера
    newHeaders.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0');
    newHeaders.set('Origin', 'https://web.telegram.org');

    return fetch(targetUrl, {
      headers: newHeaders,
    });
  },
};
