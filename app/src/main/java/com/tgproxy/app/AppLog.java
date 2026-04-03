package com.tgproxy.app;

import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Кольцевой буфер логов, доступный из UI.
 * Все логи пишутся и в android.util.Log, и сюда.
 */
public class AppLog {

    private static final int MAX_LINES = 500;
    private static final List<String> buffer = new ArrayList<>();
    private static final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);

    public interface LogListener {
        void onNewLog(String line);
    }

    private static volatile LogListener listener;

    public static void setListener(LogListener l) {
        listener = l;
    }

    public static void d(String tag, String msg) {
        Log.d(tag, msg);
        add("D", tag, msg);
    }

    public static void i(String tag, String msg) {
        Log.i(tag, msg);
        add("I", tag, msg);
    }

    public static void w(String tag, String msg) {
        Log.w(tag, msg);
        add("W", tag, msg);
    }

    public static void e(String tag, String msg) {
        Log.e(tag, msg);
        add("E", tag, msg);
    }

    public static void e(String tag, String msg, Throwable t) {
        Log.e(tag, msg, t);
        add("E", tag, msg + ": " + t.getMessage());
    }

    private static void add(String level, String tag, String msg) {
        String time = sdf.format(new Date());
        String line = time + " " + level + "/" + tag + ": " + msg;
        synchronized (buffer) {
            buffer.add(line);
            if (buffer.size() > MAX_LINES) {
                buffer.remove(0);
            }
        }
        LogListener l = listener;
        if (l != null) {
            try {
                l.onNewLog(line);
            } catch (Exception ignored) {
            }
        }
    }

    public static String getAll() {
        synchronized (buffer) {
            StringBuilder sb = new StringBuilder();
            for (String s : buffer) {
                sb.append(s).append("\n");
            }
            return sb.toString();
        }
    }

    public static List<String> getLines() {
        synchronized (buffer) {
            return new ArrayList<>(buffer);
        }
    }

    public static void clear() {
        synchronized (buffer) {
            buffer.clear();
        }
    }

    public static int size() {
        synchronized (buffer) {
            return buffer.size();
        }
    }
}
