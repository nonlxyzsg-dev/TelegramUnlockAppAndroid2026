package com.tgproxy.app;

// Logging via AppLog

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class RawWebSocket {

    private static final String TAG = "TGProxy";

    private static final int OP_BINARY = 0x2;
    private static final int OP_CLOSE = 0x8;
    private static final int OP_PING = 0x9;
    private static final int OP_PONG = 0xA;

    private final InputStream in;
    private final OutputStream out;
    private final Socket socket;
    private volatile boolean closed = false;
    private static final SecureRandom rng = new SecureRandom();

    private static SSLSocketFactory sslFactory;

    static {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[0];
                        }

                        public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {
                        }

                        public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {
                        }
                    }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            sslFactory = ctx.getSocketFactory();
        } catch (Exception e) {
            sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }

    public RawWebSocket(Socket socket) throws IOException {
        this.socket = socket;
        this.in = new java.io.BufferedInputStream(socket.getInputStream(), TgConstants.BUF);
        this.out = new java.io.BufferedOutputStream(socket.getOutputStream(), TgConstants.BUF);
    }

    private static final String[] USER_AGENTS = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    };

    // Текущая рабочая стратегия (обновляется при успехе)
    private static volatile int workingStrategy = -1;
    // IP которые заблокированы по TLS — не тратим время на перебор
    private static final java.util.Set<String> blockedIps = java.util.concurrent.ConcurrentHashMap.newKeySet();

    // Стратегии работы с SNI (не TCP-фрагментация, а изменение содержимого TLS)
    private static final int SNI_NORMAL = 0;   // Настоящий SNI (kws*.web.telegram.org)
    private static final int SNI_NONE = 1;     // Без SNI вообще
    private static final int SNI_FAKE = 2;     // Фейковый SNI (www.google.com)

    // === Upstream proxy (внешний прокси для обхода IP-блокировки) ===
    public static final int PROXY_NONE = 0;
    public static final int PROXY_HTTP = 1;    // HTTP CONNECT
    public static final int PROXY_SOCKS5 = 2;  // SOCKS5

    private static volatile int upstreamProxyType = PROXY_NONE;
    private static volatile String upstreamProxyHost = null;
    private static volatile int upstreamProxyPort = 0;

    /** Настроить upstream proxy. Вызывается из MainActivity при старте. */
    public static void setUpstreamProxy(int type, String host, int port) {
        upstreamProxyType = type;
        upstreamProxyHost = host;
        upstreamProxyPort = port;
        // Сбросить кэш стратегий при смене прокси
        workingStrategy = -1;
        blockedIps.clear();
        if (type != PROXY_NONE) {
            AppLog.i(TAG, "Upstream proxy: " + (type == PROXY_HTTP ? "HTTP" : "SOCKS5")
                    + " " + host + ":" + port);
        } else {
            AppLog.i(TAG, "Upstream proxy: disabled");
        }
    }

    // Специальные стратегии (не кодируются как sniMode*100+frag)
    private static final int STRATEGY_PLAIN_WS = 9999;    // Plain WS на порт 80 (без TLS)
    private static final int STRATEGY_DNS_RESOLVE = 9998;  // DNS-резолв свежего IP

    // Таймаут при переборе стратегий (мс)
    private static final int PROBE_TIMEOUT = 10000;

    // Фейковые SNI домены для маскировки
    private static final String[] FAKE_SNI_DOMAINS = {
        "www.google.com",
        "www.microsoft.com",
        "cdn.jsdelivr.net",
        "ajax.googleapis.com",
    };

    public static RawWebSocket connect(String ip, String domain, int timeout) throws Exception {
        // Если настроен upstream proxy — подключаемся через него
        if (upstreamProxyType != PROXY_NONE && upstreamProxyHost != null) {
            return connectViaUpstreamProxy(ip, domain, timeout);
        }

        // Ключ кэша: IP+домен (разные DC на одном IP могут вести себя по-разному)
        String cacheKey = ip + "/" + domain;

        // Если этот IP+домен заблокирован по TLS — пробуем plain WS и DNS
        if (blockedIps.contains(cacheKey)) {
            // Plain WS на порт 80 (без TLS — ТСПУ не заблокирует)
            try {
                return connectPlainWs(ip, domain, timeout);
            } catch (Exception e1) {
                AppLog.w(TAG, "Plain WS failed for " + ip + ": " + e1.getMessage());
            }
            // DNS-резолв — может другой IP не заблокирован
            try {
                String dnsIp = resolveDns(domain);
                if (dnsIp != null && !dnsIp.equals(ip) && !blockedIps.contains(dnsIp + "/" + domain)) {
                    AppLog.i(TAG, "DNS-resolved IP: " + dnsIp + " (вместо " + ip + ")");
                    return connectWithStrategy(dnsIp, domain, timeout, -2, SNI_NORMAL);
                }
            } catch (Exception e2) {
                AppLog.w(TAG, "DNS fallback failed: " + e2.getMessage());
            }
            throw new IOException(cacheKey + " blocked (TLS), using TCP fallback");
        }

        // Если уже нашли рабочую стратегию — используем с полным таймаутом
        if (workingStrategy >= 0) {
            if (workingStrategy == STRATEGY_PLAIN_WS) {
                try {
                    return connectPlainWs(ip, domain, timeout);
                } catch (Exception e) {
                    AppLog.w(TAG, "Cached PLAIN_WS failed, probing...");
                    workingStrategy = -1;
                }
            } else if (workingStrategy == STRATEGY_DNS_RESOLVE) {
                try {
                    String dnsIp = resolveDns(domain);
                    if (dnsIp != null) {
                        return connectWithStrategy(dnsIp, domain, timeout, -2, SNI_NORMAL);
                    }
                } catch (Exception e) {
                    AppLog.w(TAG, "Cached DNS strategy failed, probing...");
                    workingStrategy = -1;
                }
            } else {
                // Кодировка: sniMode * 100 + (fragStrategy + 10)
                int cachedSni = workingStrategy / 100;
                int cachedFrag = (workingStrategy % 100) - 10;
                try {
                    return connectWithStrategy(ip, domain, timeout, cachedFrag, cachedSni);
                } catch (Exception e) {
                    AppLog.w(TAG, "Cached strategy failed for " + ip + ", probing...");
                    workingStrategy = -1;
                }
            }
        }

        // Порядок перебора (SNI+DELAY первым — проверенно работает на WiFi):
        // 1. SNI+DELAY — фрагментация с задержкой (работает на WiFi)
        // 2. SNI+DIRECT — без обхода (если DPI нет)
        // 3. NO_SNI+DIRECT — для мобильной сети (ТСПУ нечего искать)
        // 4. NO_SNI+DELAY — NO_SNI + фрагментация
        // 5. FAKE_SNI+DIRECT — подмена SNI
        // 6. SNI+MOBILE — длинные паузы для медленного DPI

        int[][] strategies = {
            {SNI_NORMAL, FragmentSocket.STRATEGY_DELAY},   // SNI + фрагментация (WiFi)
            {SNI_NORMAL, -2},                              // DIRECT (нет DPI)
            {SNI_NONE,   -2},                              // NO_SNI (мобильная сеть)
            {SNI_NONE,   FragmentSocket.STRATEGY_DELAY},   // NO_SNI + фрагментация
            {SNI_FAKE,   -2},                              // FAKE_SNI
            {SNI_NORMAL, FragmentSocket.STRATEGY_MOBILE},  // Длинные паузы
        };

        Exception lastError = null;
        for (int[] combo : strategies) {
            int sniMode = combo[0];
            int fragStrategy = combo[1];
            String desc = sniModeName(sniMode) + "+" + strategyName(fragStrategy);
            try {
                RawWebSocket ws = connectWithStrategy(ip, domain, PROBE_TIMEOUT, fragStrategy, sniMode);
                // Кодируем рабочую стратегию: sniMode * 100 + (fragStrategy + 10)
                workingStrategy = sniMode * 100 + (fragStrategy + 10);
                AppLog.i(TAG, "Strategy '" + desc + "' WORKS for " + ip + "!");
                return ws;
            } catch (WsRedirectException e) {
                throw e;
            } catch (Exception e) {
                AppLog.w(TAG, "Strategy '" + desc + "' failed for " + ip + ": " + e.getMessage());
                lastError = e;
            }
        }

        // TLS-стратегии не сработали — пробуем plain WS на порт 80
        AppLog.i(TAG, "All TLS strategies failed, trying plain WS on port 80...");
        try {
            RawWebSocket ws = connectPlainWs(ip, domain, PROBE_TIMEOUT);
            workingStrategy = STRATEGY_PLAIN_WS;
            AppLog.i(TAG, "Strategy 'PLAIN_WS:80' WORKS for " + ip + "!");
            return ws;
        } catch (WsRedirectException e) {
            throw e;
        } catch (Exception e) {
            AppLog.w(TAG, "PLAIN_WS:80 failed for " + ip + ": " + e.getMessage());
            lastError = e;
        }

        // DNS-резолв — свежий IP может не быть в списке блокировки
        try {
            String dnsIp = resolveDns(domain);
            if (dnsIp != null && !dnsIp.equals(ip)) {
                AppLog.i(TAG, "DNS resolved " + domain + " → " + dnsIp + " (hardcoded was " + ip + ")");
                RawWebSocket ws = connectWithStrategy(dnsIp, domain, PROBE_TIMEOUT, -2, SNI_NORMAL);
                workingStrategy = STRATEGY_DNS_RESOLVE;
                AppLog.i(TAG, "Strategy 'DNS_RESOLVE' WORKS with IP " + dnsIp + "!");
                return ws;
            }
        } catch (WsRedirectException e) {
            throw e;
        } catch (Exception e) {
            AppLog.w(TAG, "DNS_RESOLVE failed: " + e.getMessage());
            lastError = e;
        }

        // Всё провалилось — запомнить IP+домен как заблокированный
        blockedIps.add(cacheKey);
        AppLog.w(TAG, cacheKey + " marked as blocked, will use TCP fallback");
        throw lastError != null ? lastError : new IOException("All strategies failed for " + ip);
    }

    /** Сбросить кэш заблокированных IP (например при смене сети) */
    public static void resetBlockedIps() {
        blockedIps.clear();
        workingStrategy = -1;
        AppLog.i(TAG, "Blocked IPs cache cleared");
    }

    private static String strategyName(int s) {
        switch (s) {
            case FragmentSocket.STRATEGY_DELAY: return "DELAY";
            case FragmentSocket.STRATEGY_AGGRESSIVE: return "AGGRESSIVE";
            case FragmentSocket.STRATEGY_SIMPLE: return "SIMPLE";
            case FragmentSocket.STRATEGY_MOBILE: return "MOBILE";
            case -2: return "DIRECT";
            default: return "FRAG_" + s;
        }
    }

    private static String sniModeName(int m) {
        switch (m) {
            case SNI_NORMAL: return "SNI";
            case SNI_NONE: return "NO_SNI";
            case SNI_FAKE: return "FAKE_SNI";
            default: return "SNI_" + m;
        }
    }

    /** Обратный вызов для кэшированной стратегии */
    private static RawWebSocket connectWithStrategy(String ip, String domain, int timeout, int fragStrategy, int sniMode) throws Exception {
        String desc = sniModeName(sniMode) + "+" + strategyName(fragStrategy);
        AppLog.d(TAG, "WS: trying " + ip + ":443 domain=" + domain + " strategy=" + desc);

        Socket raw = new Socket();
        raw.connect(new java.net.InetSocketAddress(ip, 443), timeout);
        raw.setSoTimeout(timeout);
        raw.setTcpNoDelay(true);
        raw.setReceiveBufferSize(262144);
        raw.setSendBufferSize(262144);

        // Определяем hostname для TLS SNI
        String tlsHost;
        switch (sniMode) {
            case SNI_NONE:
                // Передаём IP вместо hostname — Java SSLSocket не добавит SNI extension
                tlsHost = ip;
                break;
            case SNI_FAKE:
                // Фейковый SNI — DPI видит google.com, а не telegram
                tlsHost = FAKE_SNI_DOMAINS[rng.nextInt(FAKE_SNI_DOMAINS.length)];
                break;
            default:
                // Настоящий SNI
                tlsHost = domain;
                break;
        }

        SSLSocket ssl;
        if (fragStrategy == -2) {
            // Прямое подключение без фрагментации
            ssl = (SSLSocket) sslFactory.createSocket(raw, tlsHost, 443, true);
        } else {
            // Фрагментация с выбранной стратегией
            Socket fragmented = new FragmentSocket(raw, fragStrategy);
            ssl = (SSLSocket) sslFactory.createSocket(fragmented, tlsHost, 443, true);
        }

        ssl.setUseClientMode(true);

        // Для NO_SNI: явно очищаем список SNI на случай если Java всё равно добавит
        if (sniMode == SNI_NONE) {
            try {
                SSLParameters params = ssl.getSSLParameters();
                params.setServerNames(Collections.emptyList());
                ssl.setSSLParameters(params);
                AppLog.d(TAG, "SNI removed from ClientHello");
            } catch (Exception e) {
                AppLog.w(TAG, "Failed to remove SNI: " + e.getMessage());
            }
        }

        // Для FAKE_SNI: явно устанавливаем фейковый домен
        if (sniMode == SNI_FAKE) {
            try {
                SSLParameters params = ssl.getSSLParameters();
                params.setServerNames(Collections.singletonList(new SNIHostName(tlsHost)));
                ssl.setSSLParameters(params);
                AppLog.d(TAG, "SNI set to fake: " + tlsHost);
            } catch (Exception e) {
                AppLog.w(TAG, "Failed to set fake SNI: " + e.getMessage());
            }
        }

        // Маскировка TLS fingerprint под браузер Chrome
        try {
            String[] protocols = ssl.getSupportedProtocols();
            java.util.List<String> preferred = new java.util.ArrayList<>();
            for (String p : protocols) {
                if (p.equals("TLSv1.3")) preferred.add(0, p);
                else if (p.equals("TLSv1.2")) preferred.add(p);
            }
            if (!preferred.isEmpty()) {
                ssl.setEnabledProtocols(preferred.toArray(new String[0]));
            }

            String[] supportedCiphers = ssl.getSupportedCipherSuites();
            java.util.List<String> chromeLike = new java.util.ArrayList<>();
            String[] chromeOrder = {
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            };
            java.util.Set<String> supported = new java.util.HashSet<>(java.util.Arrays.asList(supportedCiphers));
            for (String c : chromeOrder) {
                if (supported.contains(c)) chromeLike.add(c);
            }
            if (chromeLike.size() >= 3) {
                ssl.setEnabledCipherSuites(chromeLike.toArray(new String[0]));
            }

            // ALPN — только http/1.1 (h2 несовместим с WebSocket upgrade!)
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                SSLParameters params = ssl.getSSLParameters();
                // Сохраняем уже установленный SNI
                java.util.List<javax.net.ssl.SNIServerName> existingSni = params.getServerNames();
                params.setApplicationProtocols(new String[]{"http/1.1"});
                if (existingSni != null) {
                    params.setServerNames(existingSni);
                }
                ssl.setSSLParameters(params);
            }
        } catch (Exception e) {
            AppLog.w(TAG, "TLS fingerprint tuning failed: " + e.getMessage());
        }

        ssl.startHandshake();
        AppLog.d(TAG, "WS: TLS handshake OK via " + desc
                + " proto=" + ssl.getSession().getProtocol()
                + " cipher=" + ssl.getSession().getCipherSuite());

        RawWebSocket ws = new RawWebSocket(ssl);

        byte[] keyBytes = new byte[16];
        rng.nextBytes(keyBytes);
        String wsKey = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP);

        // Host header — всегда настоящий домен (DPI не может прочитать HTTP внутри TLS)
        String req = "GET /apiws HTTP/1.1\r\n" +
                "Host: " + domain + "\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "Sec-WebSocket-Protocol: binary\r\n" +
                "Origin: https://web.telegram.org\r\n" +
                "User-Agent: " + USER_AGENTS[rng.nextInt(USER_AGENTS.length)] + "\r\n" +
                "\r\n";

        ws.out.write(req.getBytes("UTF-8"));
        ws.out.flush();

        int statusCode = 0;
        boolean firstLine = true;

        while (true) {
            String line = readLine(ws.in);
            if (line == null || line.isEmpty()) break;
            if (firstLine) {
                String[] parts = line.split(" ", 3);
                if (parts.length >= 2) {
                    try {
                        statusCode = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException ignored) {
                    }
                }
                firstLine = false;
            }
        }

        AppLog.d(TAG, "WS: handshake response status=" + statusCode + " domain=" + domain + " via " + desc);

        if (statusCode == 101) {
            ssl.setSoTimeout(0);
            return ws;
        }

        ws.closeQuiet();
        if (statusCode == 301 || statusCode == 302 || statusCode == 303
                || statusCode == 307 || statusCode == 308) {
            throw new WsRedirectException(statusCode);
        }
        throw new IOException("WS handshake failed: " + statusCode + " via " + desc);
    }

    /**
     * Подключение через upstream proxy (HTTP CONNECT или SOCKS5).
     * ТСПУ блокирует по IP — через внешний прокси идём в обход.
     */
    private static RawWebSocket connectViaUpstreamProxy(String ip, String domain, int timeout) throws Exception {
        AppLog.d(TAG, "WS: connecting via upstream proxy " + upstreamProxyHost + ":" + upstreamProxyPort
                + " to " + domain + ":443");

        Socket raw = new Socket();
        raw.connect(new java.net.InetSocketAddress(upstreamProxyHost, upstreamProxyPort), timeout);
        raw.setSoTimeout(timeout);
        raw.setTcpNoDelay(true);

        if (upstreamProxyType == PROXY_HTTP) {
            tunnelHttpConnect(raw, domain, 443);
        } else if (upstreamProxyType == PROXY_SOCKS5) {
            tunnelSocks5(raw, domain, 443);
        }

        AppLog.d(TAG, "WS: upstream tunnel established, starting TLS");

        // TLS поверх туннеля — используем настоящий SNI (прокси уже скрывает IP)
        SSLSocket ssl = (SSLSocket) sslFactory.createSocket(raw, domain, 443, true);
        ssl.setUseClientMode(true);

        // Chrome-like fingerprint
        try {
            String[] protocols = ssl.getSupportedProtocols();
            java.util.List<String> preferred = new java.util.ArrayList<>();
            for (String p : protocols) {
                if (p.equals("TLSv1.3")) preferred.add(0, p);
                else if (p.equals("TLSv1.2")) preferred.add(p);
            }
            if (!preferred.isEmpty()) {
                ssl.setEnabledProtocols(preferred.toArray(new String[0]));
            }
        } catch (Exception ignored) {}

        ssl.startHandshake();
        AppLog.d(TAG, "WS: TLS via proxy OK, proto=" + ssl.getSession().getProtocol());

        RawWebSocket ws = new RawWebSocket(ssl);

        byte[] keyBytes = new byte[16];
        rng.nextBytes(keyBytes);
        String wsKey = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP);

        String req = "GET /apiws HTTP/1.1\r\n" +
                "Host: " + domain + "\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "Sec-WebSocket-Protocol: binary\r\n" +
                "Origin: https://web.telegram.org\r\n" +
                "User-Agent: " + USER_AGENTS[rng.nextInt(USER_AGENTS.length)] + "\r\n" +
                "\r\n";

        ws.out.write(req.getBytes("UTF-8"));
        ws.out.flush();

        int statusCode = 0;
        boolean firstLine = true;
        while (true) {
            String line = readLine(ws.in);
            if (line == null || line.isEmpty()) break;
            if (firstLine) {
                String[] parts = line.split(" ", 3);
                if (parts.length >= 2) {
                    try { statusCode = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
                }
                firstLine = false;
            }
        }

        AppLog.d(TAG, "WS: handshake via proxy status=" + statusCode);

        if (statusCode == 101) {
            ssl.setSoTimeout(0);
            return ws;
        }

        ws.closeQuiet();
        if (statusCode >= 301 && statusCode <= 308) {
            throw new WsRedirectException(statusCode);
        }
        throw new IOException("WS via proxy failed: " + statusCode);
    }

    /** HTTP CONNECT tunnel через HTTP-прокси */
    private static void tunnelHttpConnect(Socket sock, String host, int port) throws IOException {
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        String connectReq = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n" +
                "Host: " + host + ":" + port + "\r\n" +
                "Proxy-Connection: keep-alive\r\n" +
                "\r\n";

        out.write(connectReq.getBytes("UTF-8"));
        out.flush();

        // Читаем ответ прокси
        String statusLine = readLine(in);
        if (statusLine == null) {
            throw new IOException("HTTP proxy: no response");
        }
        AppLog.d(TAG, "HTTP proxy response: " + statusLine);

        // Парсим статус
        String[] parts = statusLine.split(" ", 3);
        int status = 0;
        if (parts.length >= 2) {
            try { status = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
        }

        // Читаем остальные заголовки до пустой строки
        while (true) {
            String line = readLine(in);
            if (line == null || line.isEmpty()) break;
        }

        if (status != 200) {
            throw new IOException("HTTP proxy CONNECT failed: " + status);
        }
        AppLog.d(TAG, "HTTP CONNECT tunnel established");
    }

    /** SOCKS5 tunnel через SOCKS5-прокси */
    private static void tunnelSocks5(Socket sock, String host, int port) throws IOException {
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        // 1. Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
        out.write(new byte[]{0x05, 0x01, 0x00});
        out.flush();

        // 2. Server response
        byte[] authResp = new byte[2];
        readFully(in, authResp);
        if (authResp[0] != 0x05 || authResp[1] != 0x00) {
            throw new IOException("SOCKS5: auth not supported (method=" + (authResp[1] & 0xFF) + ")");
        }

        // 3. CONNECT request: VER=5, CMD=1(CONNECT), RSV=0, ATYP=3(DOMAIN)
        byte[] hostBytes = host.getBytes("UTF-8");
        byte[] connectReq = new byte[4 + 1 + hostBytes.length + 2];
        connectReq[0] = 0x05; // VER
        connectReq[1] = 0x01; // CMD: CONNECT
        connectReq[2] = 0x00; // RSV
        connectReq[3] = 0x03; // ATYP: DOMAIN
        connectReq[4] = (byte) hostBytes.length;
        System.arraycopy(hostBytes, 0, connectReq, 5, hostBytes.length);
        connectReq[5 + hostBytes.length] = (byte) ((port >> 8) & 0xFF);
        connectReq[6 + hostBytes.length] = (byte) (port & 0xFF);
        out.write(connectReq);
        out.flush();

        // 4. Server response (min 10 bytes for IPv4)
        byte[] resp = new byte[4];
        readFully(in, resp);
        if (resp[0] != 0x05) {
            throw new IOException("SOCKS5: bad version in response");
        }
        if (resp[1] != 0x00) {
            throw new IOException("SOCKS5: CONNECT failed, reply=" + (resp[1] & 0xFF));
        }
        // Пропускаем BIND.ADDR в зависимости от ATYP
        int atyp = resp[3] & 0xFF;
        if (atyp == 1) {
            readFully(in, new byte[4 + 2]); // IPv4 + port
        } else if (atyp == 3) {
            int dlen = in.read();
            readFully(in, new byte[dlen + 2]); // domain + port
        } else if (atyp == 4) {
            readFully(in, new byte[16 + 2]); // IPv6 + port
        }

        AppLog.d(TAG, "SOCKS5 tunnel established to " + host + ":" + port);
    }

    /**
     * Plain WebSocket на порт 80 (без TLS).
     * ТСПУ блокирует TLS к IP Telegram, но TCP:80 открыт.
     * MTProto имеет собственное шифрование, TLS не обязателен.
     */
    private static RawWebSocket connectPlainWs(String ip, String domain, int timeout) throws Exception {
        AppLog.d(TAG, "WS: trying PLAIN (no TLS) " + ip + ":80 domain=" + domain);

        Socket raw = new Socket();
        raw.connect(new java.net.InetSocketAddress(ip, 80), timeout);
        raw.setSoTimeout(timeout);
        raw.setTcpNoDelay(true);
        raw.setReceiveBufferSize(262144);
        raw.setSendBufferSize(262144);

        RawWebSocket ws = new RawWebSocket(raw);

        byte[] keyBytes = new byte[16];
        rng.nextBytes(keyBytes);
        String wsKey = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP);

        // HTTP (не HTTPS) WebSocket upgrade на порт 80
        String req = "GET /apiws HTTP/1.1\r\n" +
                "Host: " + domain + "\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "Sec-WebSocket-Protocol: binary\r\n" +
                "Origin: http://web.telegram.org\r\n" +
                "User-Agent: " + USER_AGENTS[rng.nextInt(USER_AGENTS.length)] + "\r\n" +
                "\r\n";

        ws.out.write(req.getBytes("UTF-8"));
        ws.out.flush();

        int statusCode = 0;
        boolean firstLine = true;
        while (true) {
            String line = readLine(ws.in);
            if (line == null || line.isEmpty()) break;
            if (firstLine) {
                String[] parts = line.split(" ", 3);
                if (parts.length >= 2) {
                    try { statusCode = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
                }
                firstLine = false;
            }
        }

        AppLog.d(TAG, "WS: plain handshake status=" + statusCode + " domain=" + domain);

        if (statusCode == 101) {
            raw.setSoTimeout(0);
            return ws;
        }

        ws.closeQuiet();
        if (statusCode == 301 || statusCode == 302 || statusCode == 303
                || statusCode == 307 || statusCode == 308) {
            throw new WsRedirectException(statusCode);
        }
        throw new IOException("Plain WS:80 handshake failed: " + statusCode);
    }

    /**
     * DNS-резолв домена для получения свежего IP.
     * Захардкоженные IP в TgConstants могут отличаться от актуальных.
     */
    private static String resolveDns(String domain) {
        try {
            java.net.InetAddress[] addrs = java.net.InetAddress.getAllByName(domain);
            if (addrs.length > 0) {
                String resolved = addrs[0].getHostAddress();
                AppLog.d(TAG, "DNS: " + domain + " → " + resolved
                        + " (всего " + addrs.length + " адресов)");
                return resolved;
            }
        } catch (Exception e) {
            AppLog.w(TAG, "DNS resolve failed for " + domain + ": " + e.getMessage());
        }
        return null;
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int r = in.read(buf, off, buf.length - off);
            if (r == -1) throw new IOException("EOF during proxy handshake");
            off += r;
        }
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                if (sb.length() > 0 && sb.charAt(sb.length() - 1) == '\r') {
                    sb.setLength(sb.length() - 1);
                }
                return sb.toString();
            }
            sb.append((char) c);
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    public void send(byte[] data) throws IOException {
        if (closed) throw new IOException("closed");
        byte[] frame = buildFrame(OP_BINARY, data, true);
        synchronized (out) {
            out.write(frame);
            out.flush();
        }
    }

    public void sendBatch(java.util.List<byte[]> parts) throws IOException {
        if (closed) throw new IOException("closed");
        synchronized (out) {
            for (byte[] p : parts) {
                out.write(buildFrame(OP_BINARY, p, true));
            }
            out.flush();
        }
    }

    public byte[] recv() throws IOException {
        while (!closed) {
            int[] hdr = readFrameHeader();
            int opcode = hdr[0];
            int length = hdr[1];
            boolean masked = hdr[2] == 1;

            byte[] mask = null;
            if (masked) {
                mask = readExactly(4);
            }
            byte[] payload = readExactly(length);
            if (masked && mask != null) {
                payload = xorMask(payload, mask);
            }

            if (opcode == OP_CLOSE) {
                AppLog.d(TAG, "WS recv: got CLOSE frame");
                closed = true;
                try {
                    byte[] closeData = payload.length >= 2 ? Arrays.copyOf(payload, 2) : new byte[0];
                    synchronized (out) {
                        out.write(buildFrame(OP_CLOSE, closeData, true));
                        out.flush();
                    }
                } catch (Exception ignored) {
                }
                return null;
            }

            if (opcode == OP_PING) {
                try {
                    synchronized (out) {
                        out.write(buildFrame(OP_PONG, payload, true));
                        out.flush();
                    }
                } catch (Exception ignored) {
                }
                continue;
            }

            if (opcode == OP_PONG) continue;

            if (opcode == 0x1 || opcode == 0x2) {
                return payload;
            }
        }
        return null;
    }

    public void close() {
        if (closed) return;
        closed = true;
        try {
            synchronized (out) {
                out.write(buildFrame(OP_CLOSE, new byte[0], true));
                out.flush();
            }
        } catch (Exception ignored) {
        }
        closeQuiet();
    }

    public boolean isAlive() {
        return !closed && socket != null && !socket.isClosed() && socket.isConnected();
    }

    private void closeQuiet() {
        try {
            socket.close();
        } catch (Exception ignored) {
        }
    }

    private int[] readFrameHeader() throws IOException {
        byte[] h = readExactly(2);
        int opcode = h[0] & 0x0F;
        boolean masked = (h[1] & 0x80) != 0;
        int length = h[1] & 0x7F;
        if (length == 126) {
            byte[] ext = readExactly(2);
            length = ((ext[0] & 0xFF) << 8) | (ext[1] & 0xFF);
        } else if (length == 127) {
            byte[] ext = readExactly(8);
            length = (int) ByteBuffer.wrap(ext).getLong();
        }
        return new int[]{opcode, length, masked ? 1 : 0};
    }

    private byte[] readExactly(int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r == -1) throw new IOException("EOF");
            off += r;
        }
        return buf;
    }

    private static byte[] xorMask(byte[] data, byte[] mask) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ mask[i % 4]);
        }
        return result;
    }

    private static byte[] buildFrame(int opcode, byte[] data, boolean mask) {
        int headerLen = 2;
        int len = data.length;
        if (len >= 126 && len < 65536) headerLen += 2;
        else if (len >= 65536) headerLen += 8;
        if (mask) headerLen += 4;

        byte[] frame = new byte[headerLen + len];
        int pos = 0;
        frame[pos++] = (byte) (0x80 | opcode);

        int maskBit = mask ? 0x80 : 0;
        if (len < 126) {
            frame[pos++] = (byte) (maskBit | len);
        } else if (len < 65536) {
            frame[pos++] = (byte) (maskBit | 126);
            frame[pos++] = (byte) ((len >> 8) & 0xFF);
            frame[pos++] = (byte) (len & 0xFF);
        } else {
            frame[pos++] = (byte) (maskBit | 127);
            ByteBuffer bb = ByteBuffer.allocate(8);
            bb.putLong(len);
            byte[] lb = bb.array();
            System.arraycopy(lb, 0, frame, pos, 8);
            pos += 8;
        }

        if (mask) {
            byte[] mk = new byte[4];
            rng.nextBytes(mk);
            System.arraycopy(mk, 0, frame, pos, 4);
            pos += 4;
            for (int i = 0; i < len; i++) {
                frame[pos + i] = (byte) (data[i] ^ mk[i % 4]);
            }
        } else {
            System.arraycopy(data, 0, frame, pos, len);
        }

        return frame;
    }

    public static class WsRedirectException extends IOException {
        public final int statusCode;

        public WsRedirectException(int code) {
            super("Redirect " + code);
            this.statusCode = code;
        }
    }
}
