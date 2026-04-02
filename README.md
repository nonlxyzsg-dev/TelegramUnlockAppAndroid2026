<div align="center">
  <img src="https://i.postimg.cc/wxDWc2jz/1774128022158-3.jpg" width="100%" alt="TG Proxy 2026 Banner"/>

  <h1>TG Proxy Android 2026</h1>
  <p><strong>Быстрый локальный SOCKS5-прокси со встроенным WebSocket/VLESS обходом блокировок для Telegram</strong></p>

  [![Download APK](https://img.shields.io/github/v/release/nonlxyzsg-dev/TelegramUnlockAppAndroid2026?style=for-the-badge&label=Скачать%20APK&color=green)](https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026/releases/latest)
  [![Telegram Channel](https://img.shields.io/badge/Telegram-Канал-blue?style=for-the-badge&logo=telegram)](https://t.me/TgUnlock2026)
  [![Android Support](https://img.shields.io/badge/Android-7.0+-3DDC84?style=for-the-badge&logo=android)](#)
  [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](#)
</div>

---

## Особенности

В отличие от классических MTProto-прокси, **TG Proxy 2026** работает иначе. Это локальное приложение, которое поднимает SOCKS5-сервер на вашем смартфоне (`127.0.0.1:1080`).

Трафик Telegram оборачивается в **WebSocket** или **VLESS**, пробивая блокировки провайдеров (DPI, ТСПУ) на любых сетях.

### Ключевые возможности:
- **Connection Pooling:** Пул "горячих" TLS-подключений ко всем дата-центрам Telegram. Медиа и видео грузятся моментально.
- **3 режима работы:**
  1. **Оригинал** — MTProto через WebSocket напрямую к серверам Telegram (быстрый).
  2. **Python-обходник** — Имитация браузерного трафика для обхода ТСПУ.
  3. **VLESS** — Интеграция с сервером VLESS (Xray/Reality) по одной ссылке.
- **QuickProxy MTProto:** Встроенные резервные прокси-серверы в один клик.
- **Гибкая настройка:** Свой IP, порт (1-65535), ручной выбор Telegram DC для пинга.
- **Фоновая работа:** Foreground Service с WiFi Lock и мониторингом сети.
- **Динамический порт:** Ротация портов для защиты от обнаружения.

---

## Установка

### Способ 1: Скачать готовый APK (рекомендуется)

1. Перейдите в [**Releases**](https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026/releases/latest)
2. Скачайте файл `TGProxy-x.x.x.apk`
3. Установите на Android (разрешите установку из неизвестных источников)

### Способ 2: Собрать из исходников

```bash
git clone https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026.git
cd TelegramUnlockAppAndroid2026
./gradlew assembleRelease
```

APK будет в `app/build/outputs/apk/release/`

---

## Использование

1. Откройте приложение, выберите режим: **Оригинал** / **Python** / **VLESS**
2. *(Опционально)* Укажите свой порт или оставьте `1080`
3. Нажмите **"Запустить"**
4. В **Telegram**: Настройки → Данные и память → Прокси → добавьте:
   - Тип: **SOCKS5**
   - Сервер: `127.0.0.1`
   - Порт: `1080`
5. Если локальный обход не работает — используйте **QuickProxy** кнопки внизу приложения

---

## Сборка через GitHub Actions

Проект автоматически собирается через GitHub Actions. Новый релиз создаётся одной кнопкой:

1. Перейдите в **Actions** → **Build APK**
2. Нажмите **Run workflow**
3. Выберите тип версии (patch/minor/major)
4. APK появится в разделе **Releases**

---

## Контакты

- Telegram-канал: [@TgUnlock2026](https://t.me/TgUnlock2026)
- Issues: [Создать баг-репорт](https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026/issues)

<div align="center">
  <br/>
  <i>Для свободного интернета</i>
</div>
