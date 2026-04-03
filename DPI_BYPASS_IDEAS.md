# Идеи обхода DPI блокировки Telegram WebSocket

## Проблема
DPI (Deep Packet Inspection) блокирует WebSocket-подключения к серверам Telegram
(`kws*.web.telegram.org`). TCP SYN-пакеты проходят, но TLS handshake блокируется,
потому что DPI читает SNI (Server Name Indication) из ClientHello.

## Реализованные варианты

### 1. TLS-фрагментация ClientHello ✅ (реализовано)
- **Суть**: Разбиваем TLS ClientHello на мелкие TCP-сегменты с задержками
- **Как**: FragmentSocket перехватывает первый write и шлёт по 1+50 байт
- **Стратегии**: DELAY (200мс), MOBILE (3.5с), AGGRESSIVE (побайтово), SIMPLE (без задержек)
- **Результат**: Работает на WiFi (DELAY), не работает на мобильной сети (ТСПУ реассемблирует TCP)
- **Файл**: `FragmentSocket.java`

### 2. Убрать SNI из ClientHello (NO_SNI) ✅ (реализовано)
- **Суть**: Передаём IP вместо hostname + очищаем serverNames → ClientHello без SNI extension
- **Как**: `sslFactory.createSocket(socket, ip, 443, true)` + `params.setServerNames(emptyList())`
- **Почему может работать**: DPI фильтрует по SNI domain — без SNI нечего фильтровать
- **Риск**: Сервер может потребовать SNI (но Telegram на выделенных IP, не виртуальный хостинг)
- **Файл**: `RawWebSocket.java`

### 3. Подмена SNI (FAKE_SNI / Domain Fronting) ✅ (реализовано)
- **Суть**: В TLS SNI указываем `www.google.com`, а реальный Host — в HTTP внутри TLS
- **Как**: `params.setServerNames(singletonList(new SNIHostName("www.google.com")))`
- **Почему может работать**: DPI видит google.com и пропускает; HTTP Host внутри TLS недоступен DPI
- **Риск**: Сервер отклонит TLS handshake (но у нас trustAll, принимаем любой сертификат)
- **Файл**: `RawWebSocket.java`

## Нереализованные варианты (на будущее)

### 4. Encrypted Client Hello (ECH)
- **Суть**: Шифрует SNI — DPI не видит домен
- **Плюсы**: Полноценное решение на уровне протокола
- **Минусы**: Нужна поддержка сервера + Android (не все версии TLS), нужен DNS-запрос для ECH-ключей
- **Сложность**: Высокая
- **Оценка**: Перспективно, но не все серверы и клиенты поддерживают

### 4. Padding/шум в TLS handshake
- **Суть**: Добавляем случайные TLS extensions чтобы сбить сигнатуру DPI
- **Плюсы**: Простая реализация
- **Минусы**: Требует ручной конструкции TLS ClientHello
- **Сложность**: Средняя

### 5. HTTP/2 мультиплексирование
- **Суть**: Упаковать WebSocket в HTTP/2 поток через CONNECT
- **Плюсы**: Выглядит как обычный HTTPS-трафик
- **Минусы**: Сложная реализация, нужен промежуточный сервер
- **Сложность**: Высокая

### 6. Внешний relay/прокси через VPS
- **Суть**: Свой сервер как промежуточное звено
- **Плюсы**: Гарантированно работает
- **Минусы**: Нужен VPS, по сути VPN
- **Сложность**: Средняя (но нужна инфраструктура)

### 7. QUIC/HTTP3
- **Суть**: Использовать UDP вместо TCP — другой протокол, DPI может не анализировать
- **Плюсы**: Многие DPI не инспектируют UDP
- **Минусы**: Telegram WS не поддерживает QUIC
- **Сложность**: Высокая

### 8. Разные стратегии фрагментации
Если базовая фрагментация (1+40) не помогает, можно попробовать:
- **Агрессивная**: каждый байт отдельно (1+1)
- **С паузой**: первый фрагмент, пауза 100мс, остальное
- **Обратный порядок**: большой кусок, потом мелкие
- **Случайная**: случайные размеры фрагментов

## Ссылки
- GoodbyeDPI: https://github.com/ValdikSS/GoodbyeDPI
- Zapret: https://github.com/bol-van/zapret
- DPITunnel: https://github.com/nicholasgasior/dpi-tunnel-android
- PowerTunnel: https://github.com/krlvm/PowerTunnel-Android
