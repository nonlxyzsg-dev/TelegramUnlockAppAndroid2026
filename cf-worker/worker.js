/**
 * Cloudflare Worker — WebSocket relay для Telegram MTProto.
 * v3 — WebSocketPair с правильной обработкой binary данных.
 */

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/dc(\d+)(\/.*)?$/);
    if (!match) {
      return new Response('Telegram WS Relay v3\n/dc{1-5}/apiws\n', { status: 200 });
    }

    const dc = parseInt(match[1]);
    if (dc < 1 || dc > 5) return new Response('DC 1-5', { status: 400 });

    const path = match[2] || '/apiws';
    const targetHost = `kws${dc}.web.telegram.org`;
    const targetUrl = `https://${targetHost}${path}`;

    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response(`OK dc${dc} → ${targetHost}`, { status: 200 });
    }

    // Подключаемся к Telegram через fetch
    const tgResp = await fetch(targetUrl, {
      headers: {
        'Host': targetHost,
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Protocol': 'binary',
        'Origin': 'https://web.telegram.org',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
    });

    const tgWs = tgResp.webSocket;
    if (!tgWs) {
      return new Response('Telegram rejected WS: HTTP ' + tgResp.status, { status: 502 });
    }

    // Создаём пару для клиента
    const pair = new WebSocketPair();
    const [clientWs, serverWs] = Object.values(pair);

    // Принимаем оба конца
    tgWs.accept();
    serverWs.accept();

    // Клиент → Telegram (бинарные данные без изменений)
    serverWs.addEventListener('message', (evt) => {
      try {
        if (evt.data instanceof ArrayBuffer) {
          tgWs.send(evt.data);
        } else {
          // Текстовое сообщение — конвертируем в бинарное
          const encoder = new TextEncoder();
          tgWs.send(encoder.encode(evt.data));
        }
      } catch (e) {
        try { serverWs.close(1011, 'tg send err'); } catch (_) {}
      }
    });

    // Telegram → Клиент
    tgWs.addEventListener('message', (evt) => {
      try {
        if (evt.data instanceof ArrayBuffer) {
          serverWs.send(evt.data);
        } else {
          const encoder = new TextEncoder();
          serverWs.send(encoder.encode(evt.data));
        }
      } catch (e) {
        try { tgWs.close(1011, 'client send err'); } catch (_) {}
      }
    });

    serverWs.addEventListener('close', (evt) => {
      try { tgWs.close(evt.code || 1000, evt.reason || ''); } catch (_) {}
    });
    tgWs.addEventListener('close', (evt) => {
      try { serverWs.close(evt.code || 1000, evt.reason || ''); } catch (_) {}
    });
    serverWs.addEventListener('error', () => {
      try { tgWs.close(1011, 'client err'); } catch (_) {}
    });
    tgWs.addEventListener('error', () => {
      try { serverWs.close(1011, 'tg err'); } catch (_) {}
    });

    return new Response(null, {
      status: 101,
      webSocket: clientWs,
      headers: { 'Sec-WebSocket-Protocol': 'binary' },
    });
  },
};
