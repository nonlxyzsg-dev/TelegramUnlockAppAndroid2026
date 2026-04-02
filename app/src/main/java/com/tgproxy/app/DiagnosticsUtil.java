package com.tgproxy.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;

import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class DiagnosticsUtil {

    public static final int STATUS_UNKNOWN = 0;
    public static final int STATUS_OK = 1;
    public static final int STATUS_FAIL = 2;
    public static final int STATUS_RUNNING = 3;

    public static final String NET_WIFI = "WiFi";
    public static final String NET_MOBILE = "Mobile";
    public static final String NET_NONE = "No connection";
    public static final String NET_OTHER = "Other";

    private static final ExecutorService executor = Executors.newCachedThreadPool();

    public interface DiagCallback {
        void onResult(DiagResult result);
    }

    public static class DiagResult {
        public String networkType = NET_NONE;
        public boolean internetAvailable = false;
        public boolean telegramDirect = false;
        public long telegramDirectPing = -1;
        public boolean telegramViaProxy = false;
        public long telegramProxyPing = -1;
        public boolean vpnActive = false;
        public boolean proxyRunning = false;
        public String summary = "";
    }

    public static String getNetworkType(Context ctx) {
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return NET_NONE;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network net = cm.getActiveNetwork();
            if (net == null) return NET_NONE;
            NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            if (caps == null) return NET_NONE;
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return NET_WIFI;
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return NET_MOBILE;
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "VPN";
            return NET_OTHER;
        }
        return NET_OTHER;
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

    public static long checkTelegramDirect(String ip, int port, int timeoutMs) {
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

    public static long checkTelegramViaProxy(String proxyIp, int proxyPort, String tgIp, int timeoutMs) {
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

            // SOCKS5 connect to TG DC
            byte[] ipBytes = java.net.InetAddress.getByName(tgIp).getAddress();
            byte[] req = {0x05, 0x01, 0x00, 0x01,
                    ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
                    (byte) (443 >> 8), (byte) (443 & 0xFF)};
            out.write(req);
            out.flush();

            byte[] resp = new byte[10];
            readFully(in, resp);
            s.close();

            if (resp[1] == 0x00) {
                return System.currentTimeMillis() - start;
            }
            return -1;
        } catch (Exception e) {
            return -1;
        }
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

    public static void runFullDiagnostics(Context ctx, String proxyIp, int proxyPort, DiagCallback callback) {
        executor.submit(() -> {
            DiagResult r = new DiagResult();

            // Network type
            r.networkType = getNetworkType(ctx);

            // VPN check
            r.vpnActive = isVpnActive();

            // Proxy running
            ProxyService svc = ProxyService.getInstance();
            r.proxyRunning = svc != null && svc.getEngine() != null && svc.getEngine().isRunning();

            // Internet check
            r.internetAvailable = checkInternetAvailable();
            if (!r.internetAvailable) {
                r.summary = "\u274C \u041d\u0435\u0442 \u0438\u043d\u0442\u0435\u0440\u043d\u0435\u0442\u0430";
                callback.onResult(r);
                return;
            }

            // Direct Telegram check (DC2 - most common)
            String tgDc2 = "149.154.167.220";
            r.telegramDirectPing = checkTelegramDirect(tgDc2, 443, 5000);
            r.telegramDirect = r.telegramDirectPing >= 0;

            // Proxy check
            if (r.proxyRunning) {
                r.telegramProxyPing = checkTelegramViaProxy(proxyIp, proxyPort, tgDc2, 5000);
                r.telegramViaProxy = r.telegramProxyPing >= 0;
            }

            // Build summary
            StringBuilder sb = new StringBuilder();
            sb.append("\u0421\u0435\u0442\u044c: ").append(r.networkType);
            if (r.vpnActive) sb.append(" + VPN");
            sb.append("\n");

            if (r.telegramDirect) {
                sb.append("\u2705 Telegram \u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d \u043d\u0430\u043f\u0440\u044f\u043c\u0443\u044e (")
                        .append(r.telegramDirectPing).append(" ms)\n");
                sb.append("\u2139\uFE0F \u041f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435 \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f");
            } else {
                sb.append("\u274C Telegram \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d \u043d\u0430\u043f\u0440\u044f\u043c\u0443\u044e\n");
                if (r.proxyRunning && r.telegramViaProxy) {
                    sb.append("\u2705 \u0427\u0435\u0440\u0435\u0437 \u043f\u0440\u043e\u043a\u0441\u0438 \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 (")
                            .append(r.telegramProxyPing).append(" ms)");
                } else if (r.proxyRunning) {
                    sb.append("\u274C \u041f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435 \u043f\u043e\u043c\u043e\u0433\u0430\u0435\u0442 \u2014 \u043f\u043e\u043f\u0440\u043e\u0431\u0443\u0439\u0442\u0435 \u0434\u0440\u0443\u0433\u043e\u0439 \u0440\u0435\u0436\u0438\u043c");
                } else {
                    sb.append("\u26A0\uFE0F \u0417\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u0434\u043b\u044f \u043e\u0431\u0445\u043e\u0434\u0430 \u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0438");
                }
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
