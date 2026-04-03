<div align="center">
  <img src="https://i.postimg.cc/wxDWc2jz/1774128022158-3.jpg" width="100%" alt="TG Proxy 2026 Banner"/>

  <h1>TG Proxy Android 2026</h1>
  <p><strong>Быстрый локальный SOCKS5-прокси для обхода блокировок Telegram через WebSocket</strong></p>

  <p>
    <a href="https://github.com/Genuys/TelegramUnlockAppAndroid2026">Fork</a> оригинального проекта <a href="https://github.com/Genuys">Genuys</a> с фокусом на стабильность фоновой работы, чистоту кода и автоматизацию сборки.
  </p>

  [![Download APK](https://img.shields.io/github/v/release/nonlxyzsg-dev/TelegramUnlockAppAndroid2026?style=for-the-badge&label=Скачать%20APK&color=green)](https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026/releases/latest)
  [![Telegram Channel](https://img.shields.io/badge/Telegram-@jar__with__neurons-blue?style=for-the-badge&logo=telegram)](https://t.me/jar_with_neurons)
  [![Original Project](https://img.shields.io/badge/Original-@TgUnlock2026-lightblue?style=for-the-badge&logo=telegram)](https://t.me/TgUnlock2026)
  [![Android Support](https://img.shields.io/badge/Android-7.0+-3DDC84?style=for-the-badge&logo=android)](#)
  [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](#)
</div>

---

## Что изменено в этом форке

- **Удалены сторонние прокси-серверы** — убраны захардкоженные QuickProxy (Иран/Россия), весь трафик идет только через официальные серверы Telegram
- **Удален VLESS** — убран лишний режим, приложение сфокусировано на WebSocket-обходе
- **Стабильная фоновая работа** — WiFi Lock, WebSocket keepalive (ping каждые 20 сек), таймауты сокетов, мониторинг сети. Соединение больше не отваливается при выключенном экране
- **Диагностика соединения** — встроенная проверка сети, доступности Telegram напрямую и через прокси
- **Ротация User-Agent** — 6 разных браузерных отпечатков для снижения вероятности обнаружения DPI
- **Автоматическая сборка** — GitHub Actions собирает signed APK одной кнопкой, с авто-версионированием и релизами
- **Быстрый пул соединений** — возраст пула 45 сек, retry-логика, авто-пересоздание при смене сети
- **Справка в приложении** — подробное описание режимов и инструкция прямо в интерфейсе
- **Чистый репозиторий** — убраны build-артефакты, IDE-файлы, добавлен .gitignore

---

## Как это работает

Приложение поднимает локальный SOCKS5-прокси на вашем устройстве (`127.0.0.1:1080`). Telegram подключается к этому прокси, а приложение оборачивает MTProto-трафик в WebSocket и отправляет на серверы Telegram (`kws*.web.telegram.org`). Для провайдера это выглядит как обычный HTTPS-трафик к серверам Telegram Web — DPI/ТСПУ не могут отличить его от браузера.

### Режимы работы

#### Оригинал (рекомендуется)

Самый быстрый режим. MTProto-пакеты оборачиваются в WebSocket-фреймы и отправляются на серверы Telegram через TLS. Приложение:

1. Принимает SOCKS5-соединение от Telegram
2. Определяет целевой дата-центр (DC1-DC5) по IP-адресу
3. Расшифровывает первый MTProto-пакет (AES-CTR) для определения типа соединения (основное/медиа)
4. Берет готовое WebSocket-соединение из пула или создает новое к `kws{dc}.web.telegram.org`
5. Пересылает данные в обе стороны (клиент <-> WebSocket <-> Telegram DC)

#### Python-обходник

Для случаев, когда Оригинал не работает (сильная DPI-фильтрация). Отличия от Оригинала:

- Разбивает большие пакеты на мелкие части (150-600 байт), имитируя паттерн браузерного трафика
- Добавляет случайные задержки между частями (0-5 мс)
- Делает трафик менее узнаваемым для систем глубокой инспекции пакетов

Используйте этот режим, если режим "Оригинал" не помогает обойти блокировку.

---

## Установка

### Скачать готовый APK (рекомендуется)

1. Перейдите в [**Releases**](https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026/releases/latest)
2. Скачайте `TGProxy-x.x.x.apk`
3. Установите на Android (разрешите установку из неизвестных источников)

### Собрать из исходников

```bash
git clone https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026.git
cd TelegramUnlockAppAndroid2026
./gradlew assembleRelease
```

---

## Инструкция по использованию

### Быстрый старт

1. Установите и откройте приложение
2. Выберите режим: **Оригинал** (быстрее) или **Python** (надежнее)
3. Нажмите **"Старт"**
4. В **Telegram**: Настройки -> Данные и память -> Прокси -> Добавить прокси:
   - Тип: **SOCKS5**
   - Сервер: `127.0.0.1`
   - Порт: `1080`
5. Включите добавленный прокси

### Настройки

| Параметр | Описание | По умолчанию |
|---|---|---|
| Режим | Оригинал или Python-обходник | Оригинал |
| IP | Адрес привязки прокси | 127.0.0.1 |
| Порт | Порт SOCKS5-сервера | 1080 |
| Динамический порт | Случайный порт при каждом запуске | Выкл |
| Автозапуск | Запуск прокси при открытии приложения | Выкл |
| IP Telegram | IP для проверки пинга | 149.154.167.220 |

### Диагностика

Нажмите **"Проверить соединение"** в приложении. Диагностика проверит:

- Тип сети (WiFi / Мобильная / VPN)
- Доступность интернета
- Доступность Telegram напрямую (без прокси)
- Работу прокси (если запущен)
- Пинг до серверов Telegram

### Устранение неполадок

| Проблема | Решение |
|---|---|
| Telegram не подключается | Проверьте, что прокси запущен (зеленый статус). Убедитесь, что в Telegram указан правильный IP и порт |
| Соединение отваливается | Разрешите приложению работать без ограничений батареи. Приложение запросит это при первом запуске |
| Режим "Оригинал" не работает | Переключитесь на "Python-обходник" — он лучше обходит глубокую DPI-фильтрацию |
| Высокий пинг | Это нормально при работе через WebSocket. Пинг 200-500 мс не влияет на скорость сообщений |
| Прокси работает, но Telegram "Connecting..." | Нажмите "Проверить соединение". Если Telegram доступен напрямую — прокси не нужен |
| Приложение закрывается системой | Добавьте приложение в исключения оптимизации батареи в настройках Android |

---

## Сборка через GitHub Actions

### Автоматическая сборка

1. **Actions** -> **Build APK** -> **Run workflow**
2. Выберите тип версии:
   - `patch` — багфиксы (0.0.1 -> 0.0.2)
   - `minor` — новые функции (0.0.2 -> 0.1.0)
   - `major` — крупные изменения (0.1.0 -> 1.0.0)
3. Signed APK появится в **Releases**

### Настройка подписи APK

Для signed APK добавьте 4 секрета в Settings -> Secrets and variables -> Actions:

| Секрет | Описание |
|---|---|
| `KEYSTORE_BASE64` | Keystore в base64: `base64 -w0 release.jks` |
| `KEYSTORE_PASSWORD` | Пароль от keystore |
| `KEY_ALIAS` | Alias ключа |
| `KEY_PASSWORD` | Пароль ключа |

---

## Архитектура

```
Telegram App
    |
    | SOCKS5 (127.0.0.1:1080)
    v
ProxyEngine (определяет DC, режим)
    |
    | MTProto -> WebSocket
    v
WsPool (пул TLS-соединений к DC1-DC5)
    |
    | wss://kws{dc}.web.telegram.org/apiws
    v
Telegram DC (149.154.x.x / 91.108.x.x)
```

**Ключевые компоненты:**
- `ProxyService` — Android Foreground Service с WakeLock и WiFi Lock
- `ProxyEngine` — SOCKS5-сервер, маршрутизация по режимам
- `WsPool` — пул горячих WebSocket-соединений ко всем 5 DC
- `RawWebSocket` — WebSocket-клиент с keepalive и ротацией User-Agent
- `CryptoUtils` — расшифровка MTProto init-пакетов (AES-CTR) для определения DC
- `MsgSplitter` — разбиение пакетов в режиме Python
- `DiagnosticsUtil` — диагностика сети и соединения

---

## Безопасность

- Приложение **не собирает** и **не отправляет** никакие данные
- Весь трафик идет **только** на серверы Telegram (`*.web.telegram.org`)
- Нет сторонних серверов, аналитики или рекламы
- TLS-сертификаты серверов Telegram проверяются системой Android
- Исходный код полностью открыт для аудита

---

## Благодарности

- **[Genuys](https://github.com/Genuys)** — автор оригинального проекта
- **[@TgUnlock2026](https://t.me/TgUnlock2026)** — оригинальный Telegram-канал проекта

## Контакты

- Telegram-канал форка: [@jar_with_neurons](https://t.me/jar_with_neurons)
- Issues: [Создать баг-репорт](https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026/issues)
