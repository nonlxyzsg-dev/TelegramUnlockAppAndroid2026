package com.tgproxy.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class DiagnosticsUtil {

    private static final String TAG = "TGProxy";
    private static final ExecutorService executor = Executors.newCachedThreadPool();

    public interface DiagCallback {
        void onResult(DiagResult result);
    }

    public static class DcTestResult {
        public int dc;
        public String ip;
        public long icmpPing = -1;       // ICMP ping (isReachable)
        public long tcpPing = -1;        // TCP SYN к порту 443
        public long tcpPing80 = -1;      // TCP SYN к порту 80
        public long tlsPing = -1;        // TLS handshake с SNI
        public String tlsProto = null;   // TLS версия протокола
        public String tlsError = null;   // Ошибка TLS
        public long tlsNoSniPing = -1;   // TLS handshake БЕЗ SNI
        public String tlsNoSniProto = null;
        public String tlsNoSniError = null;
        public long wsPing = -1;         // WS handshake через TLS
        public int wsStatus = 0;         // HTTP status WS upgrade
        public long plainWsPing = -1;    // Plain WS на порт 80
        public int plainWsStatus = 0;    // HTTP status plain WS
        public String wsError = null;    // Ошибка WS
        public String traceRoute = null; // Traceroute (хопы)

        public DcTestResult(int dc, String ip) {
            this.dc = dc;
            this.ip = ip;
        }
    }

    public static class DiagResult {
        public String networkType = "Нет соединения";
        public boolean internetAvailable = false;
        public boolean vpnActive = false;
        public boolean proxyRunning = false;
        public String dnsResult = null;
        public List<DcTestResult> dcResults = new ArrayList<>();
        public long proxyWsPing = -1;
        public int proxyWsStatus = 0;
        public String summary = "";
    }

    // === Определение сети ===

    public static String getNetworkType(Context ctx) {
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return "Нет соединения";

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network net = cm.getActiveNetwork();
            if (net == null) return "Нет соединения";
            NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            if (caps == null) return "Нет соединения";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "WiFi";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "Мобильная сеть";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "VPN";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "Ethernet";
            return "Другое";
        }
        return "Другое";
    }

    public static boolean isVpnActive() {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (ni.isUp() && (ni.getName().startsWith("tun") || ni.getName().startsWith("ppp")
                        || ni.getName().startsWith("pptp"))) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public static boolean checkInternetAvailable() {
        try {
            Socket s = new Socket();
            s.connect(new InetSocketAddress("1.1.1.1", 443), 3000);
            s.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // === Тесты отдельных уровней ===

    /** ICMP ping через InetAddress.isReachable (может не работать без root) */
    public static long testIcmpPing(String ip, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            InetAddress addr = InetAddress.getByName(ip);
            boolean ok = addr.isReachable(timeoutMs);
            return ok ? System.currentTimeMillis() - start : -1;
        } catch (Exception e) {
            return -1;
        }
    }

    /** TCP SYN — подключение к порту (проверяет маршрутизацию и firewall) */
    public static long testTcpConnect(String ip, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(ip, port), timeoutMs);
            s.close();
            return System.currentTimeMillis() - start;
        } catch (Exception e) {
            return -1;
        }
    }

    /** Чистый TLS handshake без WebSocket (проверяет именно TLS уровень) */
    public static Object[] testTlsHandshake(String ip, String domain, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            SSLSocketFactory factory = ctx.getSocketFactory();

            Socket raw = new Socket();
            raw.connect(new InetSocketAddress(ip, 443), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            SSLSocket ssl = (SSLSocket) factory.createSocket(raw, domain, 443, true);
            ssl.setUseClientMode(true);
            ssl.startHandshake();

            long elapsed = System.currentTimeMillis() - start;
            String proto = ssl.getSession().getProtocol();
            String cipher = ssl.getSession().getCipherSuite();
            ssl.close();
            return new Object[]{elapsed, proto, cipher, null};
        } catch (Exception e) {
            return new Object[]{-1L, null, null, e.getMessage()};
        }
    }

    /** TLS handshake БЕЗ SNI (проверяет: блокирует ли DPI по SNI или по IP) */
    public static Object[] testTlsNoSni(String ip, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            SSLSocketFactory factory = ctx.getSocketFactory();

            Socket raw = new Socket();
            raw.connect(new InetSocketAddress(ip, 443), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            // Передаём IP вместо домена — SSLSocket не добавит SNI
            SSLSocket ssl = (SSLSocket) factory.createSocket(raw, ip, 443, true);
            ssl.setUseClientMode(true);
            // Явно очищаем SNI
            javax.net.ssl.SSLParameters params = ssl.getSSLParameters();
            params.setServerNames(Collections.emptyList());
            ssl.setSSLParameters(params);

            ssl.startHandshake();
            long elapsed = System.currentTimeMillis() - start;
            String proto = ssl.getSession().getProtocol();
            ssl.close();
            return new Object[]{elapsed, proto, null, null};
        } catch (Exception e) {
            return new Object[]{-1L, null, null, e.getMessage()};
        }
    }

    /** Простой WS handshake — одна попытка без перебора стратегий (для диагностики) */
    public static long[] testWsHandshake(String ip, String domain, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            SSLSocketFactory factory = ctx.getSocketFactory();

            Socket raw = new Socket();
            raw.connect(new InetSocketAddress(ip, 443), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            SSLSocket ssl = (SSLSocket) factory.createSocket(raw, domain, 443, true);
            ssl.setUseClientMode(true);

            // ALPN — только http/1.1 (h2 ломает WS upgrade)
            if (Build.VERSION.SDK_INT >= 29) {
                javax.net.ssl.SSLParameters params = ssl.getSSLParameters();
                params.setApplicationProtocols(new String[]{"http/1.1"});
                ssl.setSSLParameters(params);
            }

            ssl.startHandshake();

            // WS upgrade
            byte[] keyBytes = new byte[16];
            new SecureRandom().nextBytes(keyBytes);
            String wsKey = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP);

            String req = "GET /apiws HTTP/1.1\r\n" +
                    "Host: " + domain + "\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "Sec-WebSocket-Protocol: binary\r\n" +
                    "Origin: https://web.telegram.org\r\n" +
                    "\r\n";

            OutputStream out = ssl.getOutputStream();
            out.write(req.getBytes("UTF-8"));
            out.flush();

            InputStream in = ssl.getInputStream();
            int statusCode = 0;
            boolean firstLine = true;
            StringBuilder lineBuf = new StringBuilder();
            int c;
            while ((c = in.read()) != -1) {
                if (c == '\n') {
                    String line = lineBuf.toString().trim();
                    if (line.isEmpty()) break;
                    if (firstLine) {
                        String[] parts = line.split(" ", 3);
                        if (parts.length >= 2) {
                            try { statusCode = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
                        }
                        firstLine = false;
                    }
                    lineBuf.setLength(0);
                } else {
                    lineBuf.append((char) c);
                }
            }

            long elapsed = System.currentTimeMillis() - start;
            ssl.close();
            return new long[]{elapsed, statusCode};
        } catch (Exception e) {
            AppLog.d(TAG, "WS diag test failed " + ip + " " + domain + ": " + e.getMessage());
            return new long[]{-1, 0};
        }
    }

    /** Тест plain WS на порт 80 (без TLS) — для диагностики */
    public static long[] testPlainWsHandshake(String ip, String domain, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            Socket raw = new Socket();
            raw.connect(new InetSocketAddress(ip, 80), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            byte[] keyBytes = new byte[16];
            new SecureRandom().nextBytes(keyBytes);
            String wsKey = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP);

            String req = "GET /apiws HTTP/1.1\r\n" +
                    "Host: " + domain + "\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "Sec-WebSocket-Protocol: binary\r\n" +
                    "Origin: http://web.telegram.org\r\n" +
                    "\r\n";

            OutputStream out = raw.getOutputStream();
            out.write(req.getBytes("UTF-8"));
            out.flush();

            InputStream in = raw.getInputStream();
            int statusCode = 0;
            boolean firstLine = true;
            StringBuilder lineBuf = new StringBuilder();
            int c;
            while ((c = in.read()) != -1) {
                if (c == '\n') {
                    String line = lineBuf.toString().trim();
                    if (line.isEmpty()) break;
                    if (firstLine) {
                        String[] parts = line.split(" ", 3);
                        if (parts.length >= 2) {
                            try { statusCode = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
                        }
                        firstLine = false;
                    }
                    lineBuf.setLength(0);
                } else {
                    lineBuf.append((char) c);
                }
            }

            long elapsed = System.currentTimeMillis() - start;
            raw.close();
            return new long[]{elapsed, statusCode};
        } catch (Exception e) {
            AppLog.d(TAG, "Plain WS diag test failed " + ip + " " + domain + ": " + e.getMessage());
            return new long[]{-1, 0};
        }
    }

    /** DNS resolve — проверяем какие IP отдаёт DNS для домена */
    public static String testDnsResolve(String domain) {
        try {
            InetAddress[] addrs = InetAddress.getAllByName(domain);
            StringBuilder sb = new StringBuilder();
            for (InetAddress a : addrs) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(a.getHostAddress());
            }
            return sb.toString();
        } catch (Exception e) {
            return "ОШИБКА: " + e.getMessage();
        }
    }

    /** Простой traceroute через TTL (без root, через TCP connect) */
    public static String testTraceroute(String ip, int maxHops) {
        StringBuilder sb = new StringBuilder();
        for (int ttl = 1; ttl <= maxHops; ttl++) {
            try {
                Socket s = new Socket();
                // Устанавливаем TTL через TrafficStats не работает без root
                // Используем InetAddress.isReachable с TTL
                InetAddress addr = InetAddress.getByName(ip);

                // На Android без root нельзя установить TTL для сокета
                // Поэтому используем Runtime.exec("ping -c 1 -t TTL -W 2 ip")
                Process p = Runtime.getRuntime().exec(
                        new String[]{"ping", "-c", "1", "-t", String.valueOf(ttl), "-W", "2", ip});
                p.waitFor();

                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(p.getInputStream()));
                String line;
                String fromLine = null;
                String timeLine = null;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("From") || line.contains("from")) {
                        fromLine = line;
                    }
                    if (line.contains("time=")) {
                        timeLine = line;
                    }
                }
                reader.close();

                if (timeLine != null) {
                    // Достигли цели
                    String time = extractTime(timeLine);
                    sb.append(ttl).append(". ").append(ip).append(" ").append(time).append("\n");
                    break;
                } else if (fromLine != null) {
                    // Промежуточный хоп
                    String hopIp = extractIpFromLine(fromLine);
                    sb.append(ttl).append(". ").append(hopIp != null ? hopIp : "???").append("\n");
                } else {
                    sb.append(ttl).append(". * * *\n");
                }
            } catch (Exception e) {
                sb.append(ttl).append(". ошибка\n");
            }
        }
        return sb.toString();
    }

    private static String extractTime(String line) {
        int idx = line.indexOf("time=");
        if (idx < 0) return "";
        int end = line.indexOf(" ", idx + 5);
        if (end < 0) end = line.length();
        return line.substring(idx, end);
    }

    private static String extractIpFromLine(String line) {
        // "From 10.0.0.1: ..." or "From 10.0.0.1 icmp_seq=..."
        int from = line.indexOf("From ");
        if (from < 0) from = line.indexOf("from ");
        if (from < 0) return null;
        int start = from + 5;
        int end = start;
        while (end < line.length() && line.charAt(end) != ':' && line.charAt(end) != ' ') end++;
        return line.substring(start, end);
    }

    /** Тест подключения через наш SOCKS5-прокси */
    public static long testViaProxy(String proxyIp, int proxyPort, String tgIp, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(proxyIp, proxyPort), timeoutMs);
            s.setSoTimeout(timeoutMs);

            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();

            // SOCKS5 auth
            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] authResp = new byte[2];
            readFully(in, authResp);

            // SOCKS5 connect
            byte[] ipBytes = InetAddress.getByName(tgIp).getAddress();
            byte[] req = {0x05, 0x01, 0x00, 0x01,
                    ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
                    (byte) (443 >> 8), (byte) (443 & 0xFF)};
            out.write(req);
            out.flush();

            byte[] resp = new byte[10];
            readFully(in, resp);

            if (resp[1] != 0x00) {
                s.close();
                return -1;
            }

            // Отправляем 64 случайных байт (как MTProto init) и ждём ответ
            byte[] fakeInit = new byte[64];
            new SecureRandom().nextBytes(fakeInit);
            out.write(fakeInit);
            out.flush();

            s.setSoTimeout(5000);
            try {
                int b = in.read();
                long elapsed = System.currentTimeMillis() - start;
                s.close();
                return elapsed;
            } catch (Exception e) {
                s.close();
                return -2; // Одностороннее соединение
            }
        } catch (Exception e) {
            return -1;
        }
    }

    // === Полная диагностика (параллельно по всем DC) ===

    /** Тестирует один DC — все уровни последовательно */
    private static DcTestResult testSingleDc(int dc, String ip) {
        String domain = "kws" + dc + ".web.telegram.org";
        DcTestResult dr = new DcTestResult(dc, ip);

        // 1. ICMP ping
        dr.icmpPing = testIcmpPing(ip, 2000);

        // 2. TCP SYN port 443
        dr.tcpPing = testTcpConnect(ip, 443, 3000);

        // 3. TCP SYN port 80
        dr.tcpPing80 = testTcpConnect(ip, 80, 3000);

        // 4. TLS handshake (с настоящим SNI) — только если TCP:443 прошёл
        if (dr.tcpPing >= 0) {
            Object[] tlsResult = testTlsHandshake(ip, domain, 5000);
            dr.tlsPing = (long) tlsResult[0];
            dr.tlsProto = (String) tlsResult[1];
            dr.tlsError = (String) tlsResult[3];
        }

        // 5. TLS без SNI — определяет блокировку по SNI vs по IP/протоколу
        if (dr.tcpPing >= 0) {
            Object[] tlsNoSni = testTlsNoSni(ip, 5000);
            dr.tlsNoSniPing = (long) tlsNoSni[0];
            dr.tlsNoSniProto = (String) tlsNoSni[1];
            dr.tlsNoSniError = (String) tlsNoSni[3];
        }

        // 6. WS upgrade через TLS — только если TLS прошёл
        if (dr.tlsPing >= 0) {
            long[] wsResult = testWsHandshake(ip, domain, 5000);
            dr.wsPing = wsResult[0];
            dr.wsStatus = (int) wsResult[1];
        }

        // 7. Plain WS на порт 80 (без TLS) — только если TCP:80 прошёл
        if (dr.tcpPing80 >= 0) {
            long[] plainWs = testPlainWsHandshake(ip, domain, 5000);
            dr.plainWsPing = plainWs[0];
            dr.plainWsStatus = (int) plainWs[1];
        }

        return dr;
    }

    /** Форматирует результат одного DC */
    private static String formatDcResult(DcTestResult dr) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n══ DC").append(dr.dc).append(" — ").append(dr.ip).append(" ══\n");

        // ICMP
        sb.append("  ICMP ping:     ");
        if (dr.icmpPing >= 0) sb.append("✅ ").append(dr.icmpPing).append(" ms\n");
        else sb.append("❌ (blocked/no root)\n");

        // TCP:443
        sb.append("  TCP :443:      ");
        if (dr.tcpPing >= 0) sb.append("✅ ").append(dr.tcpPing).append(" ms\n");
        else sb.append("❌ timeout\n");

        // TCP:80
        sb.append("  TCP :80:       ");
        if (dr.tcpPing80 >= 0) sb.append("✅ ").append(dr.tcpPing80).append(" ms\n");
        else sb.append("❌ timeout\n");

        // TLS с SNI
        if (dr.tcpPing >= 0) {
            sb.append("  TLS (SNI):     ");
            if (dr.tlsPing >= 0) {
                sb.append("✅ ").append(dr.tlsPing).append(" ms")
                        .append(" [").append(dr.tlsProto).append("]\n");
            } else {
                sb.append("❌ ").append(dr.tlsError != null ? dr.tlsError : "timeout").append("\n");
            }
        }

        // TLS без SNI
        if (dr.tcpPing >= 0) {
            sb.append("  TLS (нет SNI): ");
            if (dr.tlsNoSniPing >= 0) {
                sb.append("✅ ").append(dr.tlsNoSniPing).append(" ms")
                        .append(" [").append(dr.tlsNoSniProto).append("]\n");
            } else {
                sb.append("❌ ").append(dr.tlsNoSniError != null ? dr.tlsNoSniError : "timeout").append("\n");
            }
        }

        // WS over TLS
        if (dr.tlsPing >= 0) {
            sb.append("  WS (TLS):      ");
            if (dr.wsStatus == 101) sb.append("✅ ").append(dr.wsPing).append(" ms\n");
            else if (dr.wsStatus > 0) sb.append("⚠️ HTTP ").append(dr.wsStatus).append("\n");
            else sb.append("❌ заблокирован\n");
        }

        // Plain WS на порт 80
        if (dr.tcpPing80 >= 0) {
            sb.append("  WS (plain:80): ");
            if (dr.plainWsStatus == 101) sb.append("✅ ").append(dr.plainWsPing).append(" ms\n");
            else if (dr.plainWsStatus > 0) sb.append("⚠️ HTTP ").append(dr.plainWsStatus).append("\n");
            else sb.append("❌ не поддерживается\n");
        }

        return sb.toString();
    }

    public static void runFullDiagnostics(Context ctx, String proxyIp, int proxyPort, DiagCallback callback) {
        executor.submit(() -> {
            long diagStart = System.currentTimeMillis();
            DiagResult r = new DiagResult();

            r.networkType = getNetworkType(ctx);
            r.vpnActive = isVpnActive();

            ProxyService svc = ProxyService.getInstance();
            r.proxyRunning = svc != null && svc.getEngine() != null && svc.getEngine().isRunning();

            r.internetAvailable = checkInternetAvailable();

            StringBuilder sb = new StringBuilder();
            sb.append("═══════════════════════════════\n");
            sb.append("  ПОЛНАЯ ДИАГНОСТИКА СОЕДИНЕНИЯ\n");
            sb.append("═══════════════════════════════\n\n");

            // === Сеть ===
            sb.append("▶ Сеть: ").append(r.networkType);
            if (r.vpnActive) sb.append(" + VPN");
            sb.append("\n");
            sb.append("▶ Прокси: ").append(r.proxyRunning ? "запущен" : "остановлен").append("\n");

            if (!r.internetAvailable) {
                sb.append("▶ Интернет: ❌ Нет интернета\n");
                r.summary = sb.toString();
                callback.onResult(r);
                return;
            }
            sb.append("▶ Интернет: ✅ Есть (1.1.1.1:443 ok)\n");

            // === DNS (быстро — параллельно) ===
            sb.append("\n── DNS-резолв ──\n");
            for (Map.Entry<Integer, String> entry : TgConstants.DC_IPS.entrySet()) {
                int dc = entry.getKey();
                String domain = "kws" + dc + ".web.telegram.org";
                String resolved = testDnsResolve(domain);
                sb.append("  ").append(domain).append("\n");
                sb.append("    → ").append(resolved).append("\n");
            }

            // === Тест всех DC ПАРАЛЛЕЛЬНО ===
            int dcCount = TgConstants.DC_IPS.size();
            DcTestResult[] results = new DcTestResult[dcCount];
            CountDownLatch latch = new CountDownLatch(dcCount);

            int idx = 0;
            for (Map.Entry<Integer, String> entry : TgConstants.DC_IPS.entrySet()) {
                final int dc = entry.getKey();
                final String ip = entry.getValue();
                final int slot = idx++;
                executor.submit(() -> {
                    try {
                        results[slot] = testSingleDc(dc, ip);
                    } catch (Exception e) {
                        results[slot] = new DcTestResult(dc, ip);
                    } finally {
                        latch.countDown();
                    }
                });
            }

            // Ждём все DC (макс 30 секунд)
            try {
                latch.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}

            // === Форматируем результаты (по порядку DC) ===
            int dcWsOk = 0, dcTlsOk = 0, dcTcpOk = 0, dcPlainWsOk = 0;

            // Сортируем по DC номеру
            java.util.Arrays.sort(results, (a, b) -> {
                if (a == null) return 1;
                if (b == null) return -1;
                return Integer.compare(a.dc, b.dc);
            });

            for (DcTestResult dr : results) {
                if (dr == null) continue;
                sb.append(formatDcResult(dr));
                r.dcResults.add(dr);
                if (dr.wsStatus == 101) dcWsOk++;
                if (dr.tlsPing >= 0) dcTlsOk++;
                if (dr.tcpPing >= 0) dcTcpOk++;
                if (dr.plainWsStatus == 101) dcPlainWsOk++;
            }

            // === Traceroute (параллельно с прокси-тестом) ===
            final String[] traceResult = {null};
            final long[] proxyResult = {-3};
            CountDownLatch latch2 = new CountDownLatch(2);

            executor.submit(() -> {
                try {
                    traceResult[0] = testTraceroute(TgConstants.DC_IPS.get(2), 12);
                } finally {
                    latch2.countDown();
                }
            });

            executor.submit(() -> {
                try {
                    if (r.proxyRunning) {
                        proxyResult[0] = testViaProxy(proxyIp, proxyPort,
                                TgConstants.DC_IPS.get(2), 8000);
                    }
                } finally {
                    latch2.countDown();
                }
            });

            try {
                latch2.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}

            sb.append("\n── Traceroute к DC2 (").append(TgConstants.DC_IPS.get(2)).append(") ──\n");
            sb.append(traceResult[0] != null ? traceResult[0] : "таймаут\n");

            // === Тест через наш прокси ===
            if (r.proxyRunning) {
                sb.append("\n── Тест через наш прокси ──\n");
                if (proxyResult[0] > 0) {
                    sb.append("  ✅ Двусторонняя связь — ").append(proxyResult[0]).append(" ms\n");
                } else if (proxyResult[0] == -2) {
                    sb.append("  ❌ Данные уходят, ответ НЕ приходит (однонаправленно)\n");
                } else {
                    sb.append("  ❌ Прокси не отвечает\n");
                }
            } else {
                sb.append("\n⚠️ Запустите прокси для полной проверки\n");
            }

            // === Вывод ===
            long elapsed = (System.currentTimeMillis() - diagStart) / 1000;
            sb.append("\n═══════════════════════════════\n");
            sb.append("  ЗАКЛЮЧЕНИЕ (").append(elapsed).append(" сек)\n");
            sb.append("═══════════════════════════════\n");

            if (dcWsOk > 0) {
                sb.append("✅ WS (TLS) работает на ").append(dcWsOk).append("/5 DC\n");
                sb.append("   → Прямое подключение возможно\n");
            }
            if (dcPlainWsOk > 0) {
                sb.append("✅ WS (plain:80) работает на ").append(dcPlainWsOk).append("/5 DC\n");
                sb.append("   → Обход TLS-блокировки через порт 80\n");
            }
            if (dcWsOk == 0 && dcPlainWsOk == 0) {
                if (dcTlsOk > 0) {
                    sb.append("⚠️ TLS проходит, но WS блокируется\n");
                    sb.append("   → DPI фильтрует WebSocket upgrade\n");
                    sb.append("   → Попробуйте внешний прокси\n");
                } else if (dcTcpOk > 0) {
                    sb.append("⚠️ TCP проходит, TLS блокируется\n");
                    sb.append("   → DPI блокирует TLS к Telegram IP\n");
                    sb.append("   → Приложение попробует plain WS:80 и DNS-резолв\n");
                } else {
                    sb.append("❌ Telegram IP полностью недоступны\n");
                    sb.append("   → Нужен VPN или внешний прокси\n");
                }
            }

            r.summary = sb.toString();
            callback.onResult(r);
        });
    }

    private static void readFully(InputStream in, byte[] buf) throws java.io.IOException {
        int off = 0;
        while (off < buf.length) {
            int r = in.read(buf, off, buf.length - off);
            if (r == -1) throw new java.io.IOException("EOF");
            off += r;
        }
    }
}
