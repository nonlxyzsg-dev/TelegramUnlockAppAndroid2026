# Cloudflare Worker — Telegram WS Relay

WebSocket relay для обхода блокировки Telegram на мобильных сетях.

## Как это работает

```
Телефон → TLS к Cloudflare (не блокируется) → Worker → TLS к Telegram
```

ТСПУ видит подключение к Cloudflare, а не к Telegram — нет причин блокировать.

## Деплой (5 минут)

1. Зарегистрируйтесь на [Cloudflare](https://dash.cloudflare.com) (бесплатно)
2. Перейдите в **Workers & Pages** → **Create Worker**
3. Скопируйте содержимое `worker.js` → **Deploy**
4. Запомните URL воркера: `https://ваш-воркер.workers.dev`

## Настройка в приложении

В поле **Relay URL** введите:
```
https://ваш-воркер.workers.dev
```

Приложение будет подключаться:
```
wss://ваш-воркер.workers.dev/dc2/apiws → wss://kws2.web.telegram.org/apiws
```

## Лимиты

- Бесплатный план: **100 000 запросов/день**
- Этого достаточно для личного использования Telegram

## Проверка

Откройте в браузере:
```
https://ваш-воркер.workers.dev/
```
Должно показать: "Telegram WS Relay"
