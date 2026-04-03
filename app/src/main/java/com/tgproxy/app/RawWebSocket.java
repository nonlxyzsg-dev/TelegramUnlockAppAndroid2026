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
        // Если этот IP заблокирован по TLS — сразу exception, пусть идёт tcpFallback
        if (blockedIps.contains(ip)) {
            throw new IOException("IP " + ip + " blocked (TLS), using TCP fallback");
        }

        // Если уже нашли рабочую стратегию — используем с полным таймаутом
        // Кодировка: sniMode * 100 + (fragStrategy + 10)
        if (workingStrategy >= 0) {
            int cachedSni = workingStrategy / 100;
            int cachedFrag = (workingStrategy % 100) - 10;
            try {
                return connectWithStrategy(ip, domain, timeout, cachedFrag, cachedSni);
            } catch (Exception e) {
                AppLog.w(TAG, "Cached strategy failed for " + ip + ", probing...");
                workingStrategy = -1; // Сбрасываем — возможно сменилась сеть
            }
        }

        // Порядок перебора:
        // 1. NO_SNI — убрать SNI из ClientHello (ТСПУ нечего искать)
        // 2. FAKE_SNI + DELAY — подмена SNI на google.com + фрагментация
        // 3. DELAY — только фрагментация с задержкой (работает на WiFi)
        // 4. MOBILE — длинные паузы для медленного DPI
        // 5. DIRECT — без обхода

        int[][] strategies = {
            {SNI_NONE,   -2},                              // NO_SNI + без фрагментации
            {SNI_FAKE,   FragmentSocket.STRATEGY_DELAY},   // FAKE_SNI + фрагментация
            {SNI_FAKE,   -2},                              // FAKE_SNI + без фрагментации
            {SNI_NORMAL, FragmentSocket.STRATEGY_DELAY},   // Обычный SNI + фрагментация
            {SNI_NORMAL, FragmentSocket.STRATEGY_MOBILE},  // Обычный SNI + длинные паузы
            {SNI_NORMAL, -2},                              // DIRECT
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

        // Все стратегии провалились — запомнить IP как заблокированный
        blockedIps.add(ip);
        AppLog.w(TAG, "IP " + ip + " marked as TLS-blocked, will use TCP fallback");
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

            // ALPN
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                SSLParameters params = ssl.getSSLParameters();
                // Сохраняем уже установленный SNI
                java.util.List<javax.net.ssl.SNIServerName> existingSni = params.getServerNames();
                params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
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
