package com.tgproxy.app;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;

/**
 * Обёртка над Socket для TLS-фрагментации ClientHello.
 *
 * DPI анализирует SNI в TLS ClientHello. FragmentSocket перехватывает
 * первый write (ClientHello) и разбивает его на мелкие TCP-сегменты
 * с задержками, чтобы DPI не смог собрать SNI.
 *
 * Стратегии:
 * - DELAY: фрагментация + задержка 200мс после первого фрагмента (против DPI с TCP reassembly)
 * - AGGRESSIVE: побайтовая отправка SNI-области + задержки
 * - SIMPLE: быстрая фрагментация без задержек (для слабого DPI)
 */
public class FragmentSocket extends Socket {

    public static final int STRATEGY_DELAY = 0;      // С задержкой 200мс (для домашнего DPI)
    public static final int STRATEGY_AGGRESSIVE = 1;  // Побайтовая + задержки
    public static final int STRATEGY_SIMPLE = 2;      // Без задержек
    public static final int STRATEGY_MOBILE = 3;      // Для мобильного DPI (ТСПУ) — длинные паузы

    private final Socket delegate;
    private final FragmentOutputStream fragOut;

    public FragmentSocket(Socket delegate, int strategy) throws IOException {
        this.delegate = delegate;
        this.fragOut = new FragmentOutputStream(delegate.getOutputStream(), strategy);
    }

    @Override
    public OutputStream getOutputStream() {
        return fragOut;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return delegate.getInputStream();
    }

    // === Делегирование всех методов Socket ===

    @Override public InetAddress getInetAddress() { return delegate.getInetAddress(); }
    @Override public int getPort() { return delegate.getPort(); }
    @Override public InetAddress getLocalAddress() { return delegate.getLocalAddress(); }
    @Override public int getLocalPort() { return delegate.getLocalPort(); }
    @Override public SocketAddress getRemoteSocketAddress() { return delegate.getRemoteSocketAddress(); }
    @Override public SocketAddress getLocalSocketAddress() { return delegate.getLocalSocketAddress(); }
    @Override public boolean isConnected() { return delegate.isConnected(); }
    @Override public boolean isBound() { return delegate.isBound(); }
    @Override public boolean isClosed() { return delegate.isClosed(); }
    @Override public boolean isInputShutdown() { return delegate.isInputShutdown(); }
    @Override public boolean isOutputShutdown() { return delegate.isOutputShutdown(); }
    @Override public void close() throws IOException { delegate.close(); }
    @Override public void setSoTimeout(int t) throws SocketException { delegate.setSoTimeout(t); }
    @Override public int getSoTimeout() throws SocketException { return delegate.getSoTimeout(); }
    @Override public void setTcpNoDelay(boolean on) throws SocketException { delegate.setTcpNoDelay(on); }
    @Override public boolean getTcpNoDelay() throws SocketException { return delegate.getTcpNoDelay(); }
    @Override public void setKeepAlive(boolean on) throws SocketException { delegate.setKeepAlive(on); }
    @Override public void setSendBufferSize(int s) throws SocketException { delegate.setSendBufferSize(s); }
    @Override public void setReceiveBufferSize(int s) throws SocketException { delegate.setReceiveBufferSize(s); }
    @Override public int getSendBufferSize() throws SocketException { return delegate.getSendBufferSize(); }
    @Override public int getReceiveBufferSize() throws SocketException { return delegate.getReceiveBufferSize(); }

    private static class FragmentOutputStream extends OutputStream {
        private final OutputStream delegate;
        private final int strategy;
        private volatile boolean firstWriteDone = false;

        FragmentOutputStream(OutputStream delegate, int strategy) {
            this.delegate = delegate;
            this.strategy = strategy;
        }

        @Override
        public void write(int b) throws IOException {
            delegate.write(b);
            delegate.flush();
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (!firstWriteDone) {
                firstWriteDone = true;

                switch (strategy) {
                    case STRATEGY_AGGRESSIVE:
                        fragmentAggressive(b, off, len);
                        break;
                    case STRATEGY_SIMPLE:
                        fragmentSimple(b, off, len);
                        break;
                    case STRATEGY_MOBILE:
                        fragmentMobile(b, off, len);
                        break;
                    default:
                        fragmentWithDelay(b, off, len);
                        break;
                }
            } else {
                delegate.write(b, off, len);
            }
        }

        /**
         * Стратегия DELAY: отправить 1 байт, пауза 200мс, затем куски по 40 байт.
         * Пауза заставляет DPI сбросить буфер TCP reassembly.
         */
        private void fragmentWithDelay(byte[] b, int off, int len) throws IOException {
            AppLog.d("TGProxy", "TLS frag DELAY: " + len + " bytes");
            int pos = off;
            int end = off + len;

            // Первый байт
            delegate.write(b, pos, 1);
            delegate.flush();
            pos++;

            // Пауза — DPI reassembly timeout
            sleep(200);

            // Остальное кусками по 50 байт
            while (pos < end) {
                int chunk = Math.min(50, end - pos);
                delegate.write(b, pos, chunk);
                delegate.flush();
                pos += chunk;
            }
            AppLog.d("TGProxy", "TLS frag DELAY: done");
        }

        /**
         * Стратегия AGGRESSIVE: побайтовая отправка первых 10 байт + паузы.
         * Для сильного DPI (ТСПУ) с большим буфером reassembly.
         */
        private void fragmentAggressive(byte[] b, int off, int len) throws IOException {
            AppLog.d("TGProxy", "TLS frag AGGRESSIVE: " + len + " bytes");
            int pos = off;
            int end = off + len;

            // Первые 6 байт (TLS record header + handshake type) побайтово с паузами
            int headerBytes = Math.min(6, end - pos);
            for (int i = 0; i < headerBytes; i++) {
                delegate.write(b, pos, 1);
                delegate.flush();
                pos++;
                if (i == 0) sleep(200);  // После первого байта — длинная пауза
                else sleep(50);           // Между остальными — короткие
            }

            sleep(200); // Ещё пауза перед основными данными

            // Остальное кусками по 30 байт с микропаузами
            while (pos < end) {
                int chunk = Math.min(30, end - pos);
                delegate.write(b, pos, chunk);
                delegate.flush();
                pos += chunk;
                if (pos < end) sleep(10);
            }
            AppLog.d("TGProxy", "TLS frag AGGRESSIVE: done");
        }

        /**
         * Стратегия MOBILE: для мобильного DPI (ТСПУ).
         * ТСПУ имеет таймаут TCP reassembly ~1-3с.
         * Отправляем первый байт, ждём 2 секунды чтобы ТСПУ сбросил буфер,
         * затем остальное одним куском.
         */
        private void fragmentMobile(byte[] b, int off, int len) throws IOException {
            AppLog.d("TGProxy", "TLS frag MOBILE: " + len + " bytes");
            int pos = off;
            int end = off + len;

            // Первый байт (0x16 — TLS handshake type)
            delegate.write(b, pos, 1);
            delegate.flush();
            pos++;

            // Длинная пауза — ТСПУ сбрасывает буфер reassembly
            sleep(2000);

            // Следующие 5 байт (TLS version + length + handshake type + length)
            int headerChunk = Math.min(5, end - pos);
            delegate.write(b, pos, headerChunk);
            delegate.flush();
            pos += headerChunk;

            // Ещё пауза
            sleep(1500);

            // Остальное можно отправить целиком
            if (pos < end) {
                delegate.write(b, pos, end - pos);
                delegate.flush();
            }
            AppLog.d("TGProxy", "TLS frag MOBILE: done (3 segments, 3.5s total delay)");
        }

        /**
         * Стратегия SIMPLE: быстрая фрагментация без задержек.
         * Для слабого DPI который не делает TCP reassembly.
         */
        private void fragmentSimple(byte[] b, int off, int len) throws IOException {
            AppLog.d("TGProxy", "TLS frag SIMPLE: " + len + " bytes");
            int pos = off;
            int end = off + len;

            // 1 байт, потом по 40
            delegate.write(b, pos, 1);
            delegate.flush();
            pos++;

            while (pos < end) {
                int chunk = Math.min(40, end - pos);
                delegate.write(b, pos, chunk);
                delegate.flush();
                pos += chunk;
            }
            AppLog.d("TGProxy", "TLS frag SIMPLE: done");
        }

        private void sleep(int ms) {
            try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
        }

        @Override
        public void write(byte[] b) throws IOException {
            write(b, 0, b.length);
        }

        @Override
        public void flush() throws IOException {
            delegate.flush();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
