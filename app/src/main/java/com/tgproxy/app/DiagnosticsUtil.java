package com.tgproxy.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
// Logging via AppLog

import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DiagnosticsUtil {

    private static final String TAG = "TGProxy";
    private static final ExecutorService executor = Executors.newCachedThreadPool();

    public interface DiagCallback {
        void onResult(DiagResult result);
    }

    public static class DcTestResult {
        public int dc;
        public String ip;
        public long tcpPing = -1;
        public long wsPing = -1;
        public int wsStatus = 0;
        public String wsError = null;

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
        public List<DcTestResult> dcResults = new ArrayList<>();
        public long proxyWsPing = -1;
        public int proxyWsStatus = 0;
        public String summary = "";
    }

    public static String getNetworkType(Context ctx) {
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return "Нет соединения";

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network net = cm.getActiveNetwork();
            if (net == null) return "Нет соединения";
            NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            if (caps == null) return "Нет соединения";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "WiFi";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "Мобильная";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "VPN";
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
        } catch (Exception ignored) {
        }
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

    /**
     * Тест TCP-подключения (маленький SYN-пакет, может проходить DPI)
     */
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

    /**
     * Реальный тест: TLS handshake + WebSocket upgrade к серверу Telegram.
     * Это то что реально использует прокси — если DPI блокирует, тест покажет это.
     * Возвращает [пинг_мс, HTTP_статус_код] или [-1, 0] при ошибке.
     */
    public static long[] testWsHandshake(String ip, String domain, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            RawWebSocket ws = RawWebSocket.connect(ip, domain, timeoutMs);
            long elapsed = System.currentTimeMillis() - start;
            ws.close();
            return new long[]{elapsed, 101};
        } catch (RawWebSocket.WsRedirectException e) {
            long elapsed = System.currentTimeMillis() - start;
            return new long[]{elapsed, e.statusCode};
        } catch (Exception e) {
            AppLog.d(TAG, "WS test failed " + ip + " " + domain + ": " + e.getMessage());
            return new long[]{-1, 0};
        }
    }

    /**
     * Тест подключения через наш SOCKS5-прокси с полным WS handshake
     */
    public static long testViaProxy(String proxyIp, int proxyPort, String tgIp, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(proxyIp, proxyPort), timeoutMs);
            s.setSoTimeout(timeoutMs);

            java.io.OutputStream out = s.getOutputStream();
            java.io.InputStream in = s.getInputStream();

            // SOCKS5 auth
            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] authResp = new byte[2];
            readFully(in, authResp);

            // SOCKS5 connect
            byte[] ipBytes = java.net.InetAddress.getByName(tgIp).getAddress();
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

            // Теперь попробуем отправить 64 случайных байт (как MTProto init)
            // и подождать ответ — это покажет реальную работу
            byte[] fakeInit = new byte[64];
            new java.security.SecureRandom().nextBytes(fakeInit);
            out.write(fakeInit);
            out.flush();

            // Ждём хоть какой-то ответ (или таймаут)
            s.setSoTimeout(5000);
            try {
                int b = in.read();
                // Если получили хоть байт — связь двусторонняя
                long elapsed = System.currentTimeMillis() - start;
                s.close();
                return elapsed;
            } catch (Exception e) {
                // Таймаут — данные ушли но ответ не пришёл
                s.close();
                return -2; // Специальный код: одностороннее соединение
            }
        } catch (Exception e) {
            return -1;
        }
    }

    public static void runFullDiagnostics(Context ctx, String proxyIp, int proxyPort, DiagCallback callback) {
        executor.submit(() -> {
            DiagResult r = new DiagResult();

            r.networkType = getNetworkType(ctx);
            r.vpnActive = isVpnActive();

            ProxyService svc = ProxyService.getInstance();
            r.proxyRunning = svc != null && svc.getEngine() != null && svc.getEngine().isRunning();

            r.internetAvailable = checkInternetAvailable();

            StringBuilder sb = new StringBuilder();
            sb.append("Сеть: ").append(r.networkType);
            if (r.vpnActive) sb.append(" + VPN");
            sb.append("\n");

            if (!r.internetAvailable) {
                sb.append("❌ Нет интернета\n");
                r.summary = sb.toString();
                callback.onResult(r);
                return;
            }
            sb.append("✅ Интернет есть\n\n");

            // Тест всех DC
            sb.append("── Тест дата-центров Telegram ──\n");
            int dcOk = 0;
            int dcTcpOnly = 0;
            int dcFail = 0;

            for (Map.Entry<Integer, String> entry : TgConstants.DC_IPS.entrySet()) {
                int dc = entry.getKey();
                String ip = entry.getValue();
                String domain = "kws" + dc + ".web.telegram.org";

                DcTestResult dr = new DcTestResult(dc, ip);

                // TCP тест
                dr.tcpPing = testTcpConnect(ip, 443, 5000);

                // WebSocket тест (реальный)
                if (dr.tcpPing >= 0) {
                    long[] wsResult = testWsHandshake(ip, domain, 8000);
                    dr.wsPing = wsResult[0];
                    dr.wsStatus = (int) wsResult[1];
                }

                r.dcResults.add(dr);

                sb.append("DC").append(dc).append(" (").append(ip).append("):\n");
                if (dr.tcpPing < 0) {
                    sb.append("  ❌ TCP недоступен\n");
                    dcFail++;
                } else if (dr.wsStatus == 101) {
                    sb.append("  ✅ WS OK — ").append(dr.wsPing).append(" ms\n");
                    dcOk++;
                } else if (dr.wsStatus > 0) {
                    sb.append("  ⚠️ TCP ").append(dr.tcpPing).append("ms, WS статус ").append(dr.wsStatus).append("\n");
                    dcTcpOnly++;
                } else {
                    sb.append("  ⚠️ TCP ").append(dr.tcpPing).append("ms, WS заблокирован");
                    if (dr.wsError != null) sb.append(" (").append(dr.wsError).append(")");
                    sb.append("\n");
                    dcTcpOnly++;
                }
            }

            sb.append("\n── Итого ──\n");
            if (dcOk > 0) {
                sb.append("✅ WebSocket работает на ").append(dcOk).append("/5 DC\n");
            }
            if (dcTcpOnly > 0) {
                sb.append("⚠️ TCP проходит, WS блокируется на ").append(dcTcpOnly).append("/5 DC\n");
                sb.append("   (DPI пропускает пинг, но блокирует данные)\n");
            }
            if (dcFail > 0) {
                sb.append("❌ Полностью заблокировано ").append(dcFail).append("/5 DC\n");
            }

            // Тест через прокси
            if (r.proxyRunning) {
                sb.append("\n── Тест через прокси ──\n");
                long proxyResult = testViaProxy(proxyIp, proxyPort,
                        TgConstants.DC_IPS.get(2), 10000);

                if (proxyResult > 0) {
                    sb.append("✅ Прокси работает — двусторонняя связь (").append(proxyResult).append(" ms)\n");
                } else if (proxyResult == -2) {
                    sb.append("❌ Прокси: данные уходят, ответ НЕ приходит\n");
                    sb.append("   Проблема: одностороннее соединение\n");
                } else {
                    sb.append("❌ Прокси не отвечает\n");
                }
            } else {
                sb.append("\n⚠️ Запустите прокси для полной проверки\n");
            }

            r.summary = sb.toString();
            callback.onResult(r);
        });
    }

    private static void readFully(java.io.InputStream in, byte[] buf) throws java.io.IOException {
        int off = 0;
        while (off < buf.length) {
            int r = in.read(buf, off, buf.length - off);
            if (r == -1) throw new java.io.IOException("EOF");
            off += r;
        }
    }
}
