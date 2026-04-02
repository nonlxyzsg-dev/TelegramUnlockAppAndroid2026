<div align="center">
  <img src="https://i.postimg.cc/wxDWc2jz/1774128022158-3.jpg" width="100%" alt="TG Proxy 2026 Banner"/>

  <h1>TG Proxy Android 2026</h1>
  <p><strong>Быстрый локальный SOCKS5-прокси со встроенным WebSocket/VLESS обходом блокировок для Telegram</strong></p>

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

- **Стабильная фоновая работа** — WiFi Lock, WebSocket keepalive (ping каждые 20 сек), таймауты сокетов, мониторинг сети. Соединение больше не отваливается при выключенном экране.
- **Автоматическая сборка** — GitHub Actions собирает signed APK одной кнопкой, с авто-версионированием и релизами.
- **Быстрый пул соединений** — уменьшен возраст пула (45 сек вместо 120), авто-пересоздание при смене сети.
- **Чистый репозиторий** — убраны build-артефакты, IDE-файлы, добавлен .gitignore.

---

## Особенности

Локальное приложение, которое поднимает SOCKS5-сервер на вашем смартфоне (`127.0.0.1:1080`). Трафик Telegram оборачивается в WebSocket или VLESS, обходя блокировки провайдеров (DPI, ТСПУ).

### Ключевые возможности:
- **Connection Pooling** — пул "горячих" TLS-подключений ко всем дата-центрам Telegram
- **2 режима работы:**
  1. **Оригинал** — MTProto через WebSocket напрямую к серверам Telegram
  2. **Python-обходник** — имитация браузерного трафика для обхода ТСПУ
- **Гибкая настройка** — свой IP, порт, ручной выбор Telegram DC
- **Динамический порт** — ротация портов для защиты от обнаружения

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

## Использование

1. Откройте приложение, выберите режим: **Оригинал** / **Python**
2. Нажмите **"Запустить"**
3. В **Telegram**: Настройки → Данные и память → Прокси → добавьте:
   - Тип: **SOCKS5**
   - Сервер: `127.0.0.1`
   - Порт: `1080`

---

## Сборка через GitHub Actions

1. **Actions** → **Build APK** → **Run workflow**
2. Выберите тип версии (patch/minor/major)
3. APK появится в **Releases**

---

## Благодарности

- **[Genuys](https://github.com/Genuys)** — автор оригинального проекта
- **[@TgUnlock2026](https://t.me/TgUnlock2026)** — оригинальный Telegram-канал проекта

## Контакты

- Telegram-канал форка: [@jar_with_neurons](https://t.me/jar_with_neurons)
- Issues: [Создать баг-репорт](https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026/issues)
