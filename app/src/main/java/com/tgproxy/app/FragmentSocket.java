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
 * DPI анализирует SNI в TLS ClientHello. Если ClientHello отправлен
 * одним TCP-сегментом — DPI его читает и блокирует.
 *
 * FragmentSocket перехватывает первый write (ClientHello) и разбивает
 * его на мелкие TCP-сегменты. DPI не может собрать SNI из фрагментов.
 *
 * После handshake все данные проходят без изменений.
 */
public class FragmentSocket extends Socket {

    private final Socket delegate;
    private final FragmentOutputStream fragOut;

    /**
     * @param delegate реальный подключённый сокет (TCP_NODELAY должен быть true)
     * @param firstChunkSize размер первого фрагмента (обычно 1-5 байт)
     * @param chunkSize размер последующих фрагментов (обычно 40-50 байт)
     */
    public FragmentSocket(Socket delegate, int firstChunkSize, int chunkSize) throws IOException {
        this.delegate = delegate;
        this.fragOut = new FragmentOutputStream(delegate.getOutputStream(), firstChunkSize, chunkSize);
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

    /**
     * OutputStream который разбивает первый write на мелкие фрагменты.
     * TCP_NODELAY=true гарантирует что каждый write+flush = отдельный TCP-сегмент.
     */
    private static class FragmentOutputStream extends OutputStream {
        private final OutputStream delegate;
        private final int firstChunkSize;
        private final int chunkSize;
        private volatile boolean firstWriteDone = false;

        FragmentOutputStream(OutputStream delegate, int firstChunkSize, int chunkSize) {
            this.delegate = delegate;
            this.firstChunkSize = firstChunkSize;
            this.chunkSize = chunkSize;
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
                AppLog.d("TGProxy", "TLS fragment: splitting " + len + " bytes (first=" + firstChunkSize + " chunk=" + chunkSize + ")");

                int pos = off;
                int end = off + len;

                // Первый крошечный фрагмент — разбивает TLS record header
                int chunk = Math.min(firstChunkSize, end - pos);
                delegate.write(b, pos, chunk);
                delegate.flush();
                pos += chunk;

                // Остальные данные мелкими кусками — SNI размазывается по сегментам
                while (pos < end) {
                    chunk = Math.min(chunkSize, end - pos);
                    delegate.write(b, pos, chunk);
                    delegate.flush();
                    pos += chunk;
                }

                int segments = 1 + (int) Math.ceil((double)(len - firstChunkSize) / chunkSize);
                AppLog.d("TGProxy", "TLS fragment: sent " + len + " bytes in ~" + segments + " TCP segments");
            } else {
                // После handshake — без фрагментации
                delegate.write(b, off, len);
            }
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
