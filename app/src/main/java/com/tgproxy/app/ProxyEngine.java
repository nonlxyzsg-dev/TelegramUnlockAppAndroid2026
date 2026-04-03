package com.tgproxy.app;

// Logging via AppLog (buffered + android.util.Log)

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

public class ProxyEngine {

    private static final String TAG = "TGProxy";

    public static final int MODE_ORIGINAL = 1;
    public static final int MODE_PYTHON = 2;

    private volatile boolean running = false;
    private ServerSocket serverSocket;
    private ExecutorService pool;
    private int mode = MODE_ORIGINAL;
    private int rotateIdx = 0;
    private final WsPool wsPool = new WsPool();

    public final AtomicLong bytesUp = new AtomicLong(0);
    public final AtomicLong bytesDown = new AtomicLong(0);
    public final AtomicLong connTotal = new AtomicLong(0);
    public final AtomicLong connWs = new AtomicLong(0);
    public final AtomicLong connTcp = new AtomicLong(0);
    public final AtomicLong errors = new AtomicLong(0);

    private final Set<String> wsBlacklist = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Long> failUntil = new ConcurrentHashMap<>();
    private final Set<Socket> activeSockets = ConcurrentHashMap.newKeySet();

    private OnStatsListener statsListener;

    public interface OnStatsListener {
        void onStats(long up, long down, long total);
    }

    public void setStatsListener(OnStatsListener l) {
        this.statsListener = l;
    }

    public void setMode(int m) {
        this.mode = m;
    }

    public int getMode() {
        return mode;
    }

    public volatile String boundIp = "127.0.0.1";

    public void setBoundIp(String ip) {
        this.boundIp = (ip != null && !ip.trim().isEmpty()) ? ip.trim() : "127.0.0.1";
    }

    public void start(int port) throws IOException {
        if (running) return;
        running = true;
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);

        try {
            serverSocket.bind(new InetSocketAddress(boundIp, port));
        } catch (Exception e) {
            boundIp = "127.0.0.1";
            serverSocket.bind(new InetSocketAddress(boundIp, port));
        }

        AppLog.i(TAG, "Engine started on " + boundIp + ":" + port + " mode=" + mode);

        pool = Executors.newCachedThreadPool();
        wsPool.warmup();

        pool.submit(() -> {
            while (running && !serverSocket.isClosed()) {
                try {
                    Socket client = serverSocket.accept();
                    client.setTcpNoDelay(true);
                    connTotal.incrementAndGet();
                    pool.submit(() -> handleClient(client));
                } catch (Exception e) {
                    if (running) errors.incrementAndGet();
                }
            }
        });
    }

    public void stop() {
        running = false;
        AppLog.i(TAG, "Engine stopping");
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (Exception ignored) {
        }
        for (Socket s : activeSockets) {
            try { s.close(); } catch (Exception ignored) {}
        }
        activeSockets.clear();
        if (pool != null) pool.shutdownNow();
        pool = null;
        wsPool.stop();
    }

    public boolean isRunning() {
        return running;
    }

    private void handleClient(Socket client) {
        activeSockets.add(client);
        try {
            client.setReceiveBufferSize(524288);
            client.setSendBufferSize(524288);
            client.setTcpNoDelay(true);
            client.setKeepAlive(true);

            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            byte[] hdr = readExactly(in, 2);
            if (hdr[0] != 5) {
                AppLog.w(TAG, "Non-SOCKS5 connection, closing");
                client.close();
                return;
            }
            readExactly(in, hdr[1] & 0xFF);
            out.write(new byte[]{5, 0});
            out.flush();

            byte[] req = readExactly(in, 4);
            int cmd = req[1] & 0xFF;
            int atyp = req[3] & 0xFF;

            if (cmd != 1) {
                out.write(socks5Reply(7));
                out.flush();
                client.close();
                return;
            }

            String dst;
            if (atyp == 1) {
                byte[] addr = readExactly(in, 4);
                dst = (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "." + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
            } else if (atyp == 3) {
                int dlen = readExactly(in, 1)[0] & 0xFF;
                dst = new String(readExactly(in, dlen), "UTF-8");
            } else if (atyp == 4) {
                byte[] addr = readExactly(in, 16);
                dst = java.net.InetAddress.getByAddress(addr).getHostAddress();
            } else {
                out.write(socks5Reply(8));
                out.flush();
                client.close();
                return;
            }

            byte[] portBytes = readExactly(in, 2);
            int port = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);

            AppLog.d(TAG, "SOCKS5 CONNECT " + dst + ":" + port);

            if (dst.contains(":")) {
                AppLog.w(TAG, "IPv6 rejected: " + dst);
                out.write(socks5Reply(5));
                out.flush();
                client.close();
                return;
            }

            switch (mode) {
                case MODE_PYTHON:
                    handlePython(client, in, out, dst, port);
                    break;
                default:
                    handleOriginal(client, in, out, dst, port);
                    break;
            }
        } catch (Exception e) {
            AppLog.e(TAG, "handleClient error: " + e.getMessage());
            errors.incrementAndGet();
        } finally {
            activeSockets.remove(client);
            try {
                client.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void handleOriginal(Socket client, InputStream in, OutputStream out, String dst, int port) throws Exception {
        boolean isTg = TgConstants.isTelegramIp(dst);
        AppLog.d(TAG, "handleOriginal dst=" + dst + ":" + port + " isTelegram=" + isTg);

        if (!isTg) {
            handlePassthrough(client, in, out, dst, port);
            return;
        }

        out.write(socks5Reply(0));
        out.flush();

        byte[] init = readExactly(in, 64);
        if (TgConstants.isHttp(init)) {
            AppLog.w(TAG, "HTTP detected, closing");
            client.close();
            return;
        }

        int[] dcInfo = CryptoUtils.dcFromInit(init);
        int dc = -1;
        boolean isMedia = false;

        if (dcInfo != null) {
            dc = dcInfo[0];
            isMedia = dcInfo[1] == 1;
            AppLog.d(TAG, "dcFromInit: dc=" + dc + " media=" + isMedia);
        } else {
            AppLog.d(TAG, "dcFromInit returned null");
        }

        if (dcInfo == null && TgConstants.IP_TO_DC.containsKey(dst)) {
            int[] info = TgConstants.IP_TO_DC.get(dst);
            dc = info[0];
            isMedia = info[1] == 1;
            AppLog.d(TAG, "IP_TO_DC fallback: dc=" + dc + " media=" + isMedia);
        }

        if (dc < 1 || dc > 5 || !TgConstants.DC_IPS.containsKey(dc)) {
            AppLog.w(TAG, "Invalid DC=" + dc + ", TCP fallback");
            tcpFallback(client, in, out, dst, port, init);
            return;
        }

        String dcKey = dc + ":" + isMedia;
        long now = System.currentTimeMillis();

        if (wsBlacklist.contains(dcKey)) {
            AppLog.w(TAG, "DC " + dcKey + " blacklisted, TCP fallback");
            tcpFallback(client, in, out, dst, port, init);
            return;
        }

        Long fu = failUntil.get(dcKey);
        if (fu != null) {
            if (now < fu) {
                AppLog.w(TAG, "DC " + dcKey + " in cooldown, TCP fallback");
                tcpFallback(client, in, out, dst, port, init);
                return;
            }
            failUntil.remove(dcKey);
        }

        String[] domains = TgConstants.wsDomains(dc, isMedia);
        String targetIp = TgConstants.DC_IPS.get(dc);

        AppLog.d(TAG, "Trying WS pool for dc=" + dc + " ip=" + targetIp);
        RawWebSocket ws = wsPool.get(dc, isMedia, targetIp, domains);
        boolean hadRedirect = false;
        boolean allRedirects = true;

        if (ws != null) {
            AppLog.d(TAG, "Got WS from pool, alive=" + ws.isAlive());
        } else {
            AppLog.d(TAG, "Pool empty, trying direct connect");
            for (String domain : domains) {
                try {
                    AppLog.d(TAG, "WS connect: " + targetIp + " domain=" + domain);
                    ws = RawWebSocket.connect(targetIp, domain, 10000);
                    allRedirects = false;
                    AppLog.d(TAG, "WS connect SUCCESS");
                    break;
                } catch (RawWebSocket.WsRedirectException e) {
                    hadRedirect = true;
                    AppLog.w(TAG, "WS redirect " + e.statusCode + " domain=" + domain);
                    errors.incrementAndGet();
                    continue;
                } catch (Exception e) {
                    allRedirects = false;
                    AppLog.e(TAG, "WS connect FAIL domain=" + domain + ": " + e.getMessage());
                    errors.incrementAndGet();
                    break;
                }
            }
        }

        if (ws == null) {
            if (hadRedirect && allRedirects) {
                wsBlacklist.add(dcKey);
                AppLog.w(TAG, "All redirects, blacklisting DC " + dcKey);
            } else {
                failUntil.put(dcKey, now + (long) (TgConstants.COOLDOWN * 1000));
                AppLog.w(TAG, "WS failed, cooldown DC " + dcKey);
            }
            tcpFallback(client, in, out, dst, port, init);
            return;
        }

        failUntil.remove(dcKey);
        connWs.incrementAndGet();

        AppLog.i(TAG, "Sending init (" + init.length + " bytes) via WS to dc=" + dc);
        ws.send(init);
        AppLog.d(TAG, "Starting bridgeWs for dc=" + dc);
        bridgeWs(in, out, ws, null);
    }

    private void handlePython(Socket client, InputStream in, OutputStream out, String dst, int port) throws Exception {
        boolean isTg = TgConstants.isTelegramIp(dst);
        AppLog.d(TAG, "handlePython dst=" + dst + ":" + port + " isTelegram=" + isTg);

        if (!isTg) {
            handlePassthrough(client, in, out, dst, port);
            return;
        }

        out.write(socks5Reply(0));
        out.flush();

        byte[] init = readExactly(in, 64);
        if (TgConstants.isHttp(init)) {
            AppLog.w(TAG, "HTTP detected, closing");
            client.close();
            return;
        }

        int[] dcInfo = CryptoUtils.dcFromInit(init);
        boolean patched = false;
        int dc = -1;
        boolean isMedia = false;

        if (dcInfo != null) {
            dc = dcInfo[0];
            isMedia = dcInfo[1] == 1;
            AppLog.d(TAG, "dcFromInit: dc=" + dc + " media=" + isMedia);
        } else {
            AppLog.d(TAG, "dcFromInit returned null");
        }

        if (dcInfo == null && TgConstants.IP_TO_DC.containsKey(dst)) {
            int[] info = TgConstants.IP_TO_DC.get(dst);
            dc = info[0];
            isMedia = info[1] == 1;
            if (TgConstants.DC_IPS.containsKey(dc)) {
                init = CryptoUtils.patchDc(init, isMedia ? dc : -dc);
                patched = true;
                AppLog.d(TAG, "Patched DC: " + dc + " media=" + isMedia);
            }
        }

        if (dc < 1 || dc > 5 || !TgConstants.DC_IPS.containsKey(dc)) {
            AppLog.w(TAG, "Invalid DC=" + dc + ", TCP fallback");
            tcpFallback(client, in, out, dst, port, init);
            return;
        }

        String dcKey = dc + ":" + isMedia;
        long now = System.currentTimeMillis();

        if (wsBlacklist.contains(dcKey)) {
            AppLog.w(TAG, "DC " + dcKey + " blacklisted, TCP fallback");
            tcpFallback(client, in, out, dst, port, init);
            return;
        }

        Long fu = failUntil.get(dcKey);
        if (fu != null) {
            if (now < fu) {
                AppLog.w(TAG, "DC " + dcKey + " in cooldown, TCP fallback");
                tcpFallback(client, in, out, dst, port, init);
                return;
            }
            failUntil.remove(dcKey);
        }

        String[] domains = TgConstants.wsDomains(dc, isMedia);
        String targetIp = TgConstants.DC_IPS.get(dc);

        AppLog.d(TAG, "Trying WS pool for dc=" + dc + " ip=" + targetIp);
        RawWebSocket ws = wsPool.get(dc, isMedia, targetIp, domains);
        boolean hadRedirect = false;
        boolean allRedirects = true;

        if (ws != null) {
            AppLog.d(TAG, "Got WS from pool, alive=" + ws.isAlive());
        } else {
            AppLog.d(TAG, "Pool empty, trying direct connect");
            for (String domain : domains) {
                try {
                    AppLog.d(TAG, "WS connect: " + targetIp + " domain=" + domain);
                    ws = RawWebSocket.connect(targetIp, domain, 10000);
                    allRedirects = false;
                    AppLog.d(TAG, "WS connect SUCCESS");
                    break;
                } catch (RawWebSocket.WsRedirectException e) {
                    hadRedirect = true;
                    AppLog.w(TAG, "WS redirect " + e.statusCode + " domain=" + domain);
                    errors.incrementAndGet();
                    continue;
                } catch (Exception e) {
                    allRedirects = false;
                    AppLog.e(TAG, "WS connect FAIL domain=" + domain + ": " + e.getMessage());
                    errors.incrementAndGet();
                    break;
                }
            }
        }

        if (ws == null) {
            if (hadRedirect && allRedirects) {
                wsBlacklist.add(dcKey);
                AppLog.w(TAG, "All redirects, blacklisting DC " + dcKey);
            } else {
                failUntil.put(dcKey, now + (long) (TgConstants.COOLDOWN * 1000));
                AppLog.w(TAG, "WS failed, cooldown DC " + dcKey);
            }
            tcpFallback(client, in, out, dst, port, init);
            return;
        }

        failUntil.remove(dcKey);
        connWs.incrementAndGet();

        AppLog.i(TAG, "Sending init (" + init.length + " bytes) via WS to dc=" + dc + " patched=" + patched);
        ws.send(init);
        AppLog.d(TAG, "Starting bridgeWs for dc=" + dc);
        bridgeWs(in, out, ws, patched ? init : null);
    }

    public void refreshPool() {
        AppLog.d(TAG, "refreshPool called");
        wsPool.refresh();
    }

    public void clearPool() {
        AppLog.d(TAG, "clearPool called");
        wsPool.clear();
    }

    private void handlePassthrough(Socket client, InputStream in, OutputStream out, String dst, int port) throws Exception {
        AppLog.d(TAG, "Passthrough to " + dst + ":" + port);
        Socket remote = new Socket();
        try {
            remote.connect(new InetSocketAddress(dst, port), 10000);
            remote.setReceiveBufferSize(524288);
            remote.setSendBufferSize(524288);
            remote.setTcpNoDelay(true);
            remote.setKeepAlive(true);
        } catch (Exception e) {
            AppLog.e(TAG, "Passthrough connect failed: " + e.getMessage());
            try {
                out.write(socks5Reply(5));
                out.flush();
            } catch (Exception ignored) {}
            try { client.close(); } catch (Exception ignored) {}
            return;
        }

        out.write(socks5Reply(0));
        out.flush();

        InputStream remoteIn = remote.getInputStream();
        OutputStream remoteOut = remote.getOutputStream();

        Thread t1 = new Thread(() -> pipe(in, remoteOut));
        Thread t2 = new Thread(() -> pipe(remoteIn, out));
        t1.start();
        t2.start();
        try {
            t1.join();
        } catch (InterruptedException ignored) {
        }
        try {
            t2.join();
        } catch (InterruptedException ignored) {
        }
        try {
            remote.close();
        } catch (Exception ignored) {
        }
    }

    private void tcpFallback(Socket client, InputStream in, OutputStream out, String dst, int port, byte[] init) {
        connTcp.incrementAndGet();
        AppLog.i(TAG, "TCP fallback to " + dst + ":" + port);
        try {
            Socket remote = new Socket();
            remote.connect(new InetSocketAddress(dst, port), 10000);
            remote.setReceiveBufferSize(524288);
            remote.setSendBufferSize(524288);
            remote.setTcpNoDelay(true);
            remote.setKeepAlive(true);
            InputStream remoteIn = remote.getInputStream();
            OutputStream remoteOut = remote.getOutputStream();
            remoteOut.write(init);
            remoteOut.flush();
            AppLog.d(TAG, "TCP fallback connected, bridging");

            Thread t1 = new Thread(() -> pipeWithStats(in, remoteOut, true));
            Thread t2 = new Thread(() -> pipeWithStats(remoteIn, out, false));
            t1.start();
            t2.start();
            try {
                t1.join();
            } catch (InterruptedException ignored) {
            }
            try {
                t2.join();
            } catch (InterruptedException ignored) {
            }
            try {
                remote.close();
            } catch (Exception ignored) {
            }
        } catch (Exception e) {
            AppLog.e(TAG, "TCP fallback error: " + e.getMessage());
            errors.incrementAndGet();
        }
    }

    private void bridgeWs(InputStream in, OutputStream out, RawWebSocket ws, byte[] initForSplit) {
        MsgSplitter splitter = null;
        if (initForSplit != null) {
            try {
                splitter = new MsgSplitter(initForSplit);
            } catch (Exception ignored) {
            }
        }
        final MsgSplitter spl = splitter;

        Thread upThread = new Thread(() -> {
            try {
                byte[] buf = new byte[TgConstants.BUF];
                int n;
                while ((n = in.read(buf)) > 0) {
                    byte[] chunk = Arrays.copyOf(buf, n);
                    bytesUp.addAndGet(n);
                    if (spl != null) {
                        List<byte[]> parts = spl.split(chunk);
                        if (parts.size() > 1) {
                            ws.sendBatch(parts);
                        } else {
                            ws.send(parts.get(0));
                        }
                    } else {
                        ws.send(chunk);
                    }
                    notifyStats();
                }
                AppLog.d(TAG, "bridgeWs upThread: client stream ended");
            } catch (Exception e) {
                AppLog.e(TAG, "bridgeWs upThread error: " + e.getMessage());
            } finally {
                ws.close();
                try {
                    in.close();
                    out.close();
                } catch (Exception ignored) {}
            }
        });

        Thread downThread = new Thread(() -> {
            try {
                AppLog.d(TAG, "bridgeWs downThread: waiting for WS data...");
                while (ws.isAlive()) {
                    byte[] data = ws.recv();
                    if (data == null) {
                        AppLog.w(TAG, "bridgeWs downThread: recv returned null (WS closed)");
                        break;
                    }
                    bytesDown.addAndGet(data.length);
                    out.write(data);
                    out.flush();
                    notifyStats();
                }
                AppLog.d(TAG, "bridgeWs downThread: WS no longer alive");
            } catch (Exception e) {
                AppLog.e(TAG, "bridgeWs downThread error: " + e.getMessage());
            } finally {
                ws.close();
                try {
                    in.close();
                    out.close();
                } catch (Exception ignored) {}
            }
        });

        upThread.start();
        downThread.start();

        try {
            upThread.join();
        } catch (InterruptedException ignored) {
        }
        try {
            downThread.join();
        } catch (InterruptedException ignored) {
        }
        AppLog.d(TAG, "bridgeWs finished");
    }

    private void pipe(InputStream in, OutputStream out) {
        try {
            byte[] buf = new byte[TgConstants.BUF];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (Exception ignored) {
        } finally {
            try { in.close(); } catch (Exception ignored) {}
            try { out.close(); } catch (Exception ignored) {}
        }
    }

    private void pipeWithStats(InputStream in, OutputStream out, boolean isUp) {
        try {
            byte[] buf = new byte[TgConstants.BUF];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (isUp) bytesUp.addAndGet(n);
                else bytesDown.addAndGet(n);
                out.write(buf, 0, n);
                out.flush();
                notifyStats();
            }
        } catch (Exception ignored) {
        } finally {
            try { in.close(); } catch (Exception ignored) {}
            try { out.close(); } catch (Exception ignored) {}
        }
    }

    private void notifyStats() {
        if (statsListener != null) {
            statsListener.onStats(bytesUp.get(), bytesDown.get(), connTotal.get());
        }
    }

    private static byte[] socks5Reply(int status) {
        return new byte[]{5, (byte) status, 0, 1, 0, 0, 0, 0, 0, 0};
    }

    private static byte[] readExactly(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r == -1) throw new IOException("EOF");
            off += r;
        }
        return buf;
    }
}
