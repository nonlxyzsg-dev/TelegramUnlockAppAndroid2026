#!/usr/bin/env python3
"""
Тестирование подключения к Telegram WebSocket серверам.
Запускай с того же устройства/сети что и телефон чтобы проверить
блокирует ли DPI подключения с ПК тоже.

Использование:
    python3 test_telegram_ws.py

Требования: Python 3.6+ (стандартная библиотека)
"""

import socket
import ssl
import time
import sys
import hashlib
import base64
import os
import struct

# Все дата-центры Telegram
DC_IPS = {
    1: "149.154.175.53",
    2: "149.154.167.220",
    3: "149.154.175.100",
    4: "149.154.167.220",
    5: "91.108.56.116",
}

def test_tcp(ip, port=443, timeout=5):
    """Тест TCP-подключения"""
    try:
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        elapsed = int((time.time() - start) * 1000)
        s.close()
        return elapsed
    except Exception as e:
        return f"FAIL: {e}"

def test_tls_standard(ip, domain, timeout=10):
    """Тест TLS: стандартный Python (аналог Java SSLSocket)"""
    try:
        start = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))

        ssock = ctx.wrap_socket(s, server_hostname=domain)
        elapsed = int((time.time() - start) * 1000)
        proto = ssock.version()
        cipher = ssock.cipher()
        ssock.close()
        return f"OK {elapsed}ms proto={proto} cipher={cipher[0]}"
    except Exception as e:
        return f"FAIL: {e}"

def test_tls_no_sni(ip, timeout=10):
    """Тест TLS без SNI"""
    try:
        start = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))

        # Без server_hostname — не будет SNI
        ssock = ctx.wrap_socket(s)
        elapsed = int((time.time() - start) * 1000)
        ssock.close()
        return f"OK {elapsed}ms (без SNI)"
    except Exception as e:
        return f"FAIL: {e}"

def test_tls_fragmented(ip, domain, timeout=10):
    """Тест TLS с фрагментацией ClientHello (аналог FragmentSocket)"""
    try:
        start = time.time()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((ip, 443))

        # Используем низкоуровневый SSL для перехвата ClientHello
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Оборачиваем сокет с do_handshake_on_connect=False
        ssock = ctx.wrap_socket(s, server_hostname=domain, do_handshake_on_connect=False)

        # Вручную делаем handshake — Python всё равно отправляет ClientHello целиком
        # Но мы можем попробовать через BIO...
        # К сожалению, Python ssl модуль не даёт контролировать фрагментацию
        # Просто делаем стандартный handshake
        ssock.do_handshake()
        elapsed = int((time.time() - start) * 1000)
        ssock.close()
        return f"OK {elapsed}ms (Python TLS)"
    except Exception as e:
        return f"FAIL: {e}"

def test_ws_handshake(ip, domain, timeout=10):
    """Полный тест: TLS + WebSocket upgrade (как делает прокси)"""
    try:
        start = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))

        ssock = ctx.wrap_socket(s, server_hostname=domain)
        tls_time = int((time.time() - start) * 1000)

        # WebSocket upgrade
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET /apiws HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: binary\r\n"
            f"Origin: https://web.telegram.org\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0\r\n"
            f"\r\n"
        )
        ssock.sendall(req.encode())

        # Читаем HTTP ответ
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk

        elapsed = int((time.time() - start) * 1000)
        ssock.close()

        first_line = response.split(b"\r\n")[0].decode()
        status = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else "?"

        if status == "101":
            return f"OK {elapsed}ms (TLS={tls_time}ms, WS status 101)"
        else:
            return f"WS status {status} ({elapsed}ms)"
    except Exception as e:
        return f"FAIL: {e}"

def test_tls13_only(ip, domain, timeout=10):
    """Тест TLS 1.3 (как Chrome)"""
    try:
        start = time.time()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))

        ssock = ctx.wrap_socket(s, server_hostname=domain)
        elapsed = int((time.time() - start) * 1000)
        proto = ssock.version()
        ssock.close()
        return f"OK {elapsed}ms proto={proto}"
    except Exception as e:
        return f"FAIL: {e}"

def main():
    print("=" * 60)
    print("  Тест подключения к Telegram WebSocket серверам")
    print("  Запущен:", time.strftime("%Y-%m-%d %H:%M:%S"))
    print("  Python:", sys.version.split()[0])
    print("  OpenSSL:", ssl.OPENSSL_VERSION)
    print("=" * 60)

    for dc, ip in sorted(DC_IPS.items()):
        domain = f"kws{dc}.web.telegram.org"
        print(f"\n--- DC{dc} ({ip}) → {domain} ---")

        # TCP
        result = test_tcp(ip)
        print(f"  TCP:           {result}{'ms' if isinstance(result, int) else ''}")

        if isinstance(result, str) and "FAIL" in result:
            print(f"  (пропуск TLS тестов — TCP не работает)")
            continue

        # TLS стандартный
        print(f"  TLS стандарт:  {test_tls_standard(ip, domain)}")

        # TLS без SNI
        print(f"  TLS без SNI:   {test_tls_no_sni(ip)}")

        # TLS 1.3
        print(f"  TLS 1.3:       {test_tls13_only(ip, domain)}")

        # Полный WS handshake
        print(f"  WS handshake:  {test_ws_handshake(ip, domain)}")

    print("\n" + "=" * 60)
    print("  Тестирование завершено")
    print("=" * 60)
    print("\nЕсли ВСЕ TLS тесты FAIL — DPI блокирует TLS к IP Telegram")
    print("Если TLS OK но WS FAIL — DPI блокирует WebSocket upgrade")
    print("Если TLS без SNI OK — DPI фильтрует по SNI")
    print("Если TLS 1.3 OK а стандарт FAIL — DPI фильтрует по TLS fingerprint")
    print("\nСкопируй результаты и отправь для анализа!")

if __name__ == "__main__":
    main()
