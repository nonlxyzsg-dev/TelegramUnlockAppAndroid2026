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

    // Создаём пару WebSocket: client ↔ server
    const [clientWs, serverWs] = Object.values(new WebSocketPair());

    // Подключаемся к Telegram через fetch (Cloudflare Workers поддерживают WS через fetch)
    const telegramResp = await fetch(targetUrl, {
      headers: {
        'Host': targetHost,
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Key': request.headers.get('Sec-WebSocket-Key') || '',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Protocol': request.headers.get('Sec-WebSocket-Protocol') || 'binary',
        'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0',
        'Origin': 'https://web.telegram.org',
      },
    });

    // Проверяем что Telegram принял WebSocket
    const telegramWs = telegramResp.webSocket;
    if (!telegramWs) {
      serverWs.close();
      return new Response('Telegram did not accept WebSocket (HTTP ' + telegramResp.status + ')', { status: 502 });
    }

    // Принимаем оба WebSocket
    serverWs.accept();
    telegramWs.accept();

    // Пробрасываем данные: клиент → Telegram
    serverWs.addEventListener('message', event => {
      try {
        telegramWs.send(event.data);
      } catch (e) {
        serverWs.close(1011, 'Telegram send error');
      }
    });

    serverWs.addEventListener('close', event => {
      try { telegramWs.close(event.code, event.reason); } catch (e) {}
    });

    serverWs.addEventListener('error', event => {
      try { telegramWs.close(1011, 'Client error'); } catch (e) {}
    });

    // Пробрасываем данные: Telegram → клиент
    telegramWs.addEventListener('message', event => {
      try {
        serverWs.send(event.data);
      } catch (e) {
        telegramWs.close(1011, 'Client send error');
      }
    });

    telegramWs.addEventListener('close', event => {
      try { serverWs.close(event.code, event.reason); } catch (e) {}
    });

    telegramWs.addEventListener('error', event => {
      try { serverWs.close(1011, 'Telegram error'); } catch (e) {}
    });

    // Возвращаем клиентский WebSocket
    return new Response(null, {
      status: 101,
      webSocket: clientWs,
    });
  },
};
