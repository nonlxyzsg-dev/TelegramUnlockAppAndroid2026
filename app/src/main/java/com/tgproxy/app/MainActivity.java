package com.tgproxy.app;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.preference.PreferenceManager;

import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private Button btnStart, btnStop;
    private TextView tvStatus, tvAddress, tvPort, tvTgLink, tvPing, tvTraffic, tvUptime;
    private RadioGroup rgMode;
    private RadioButton rbOriginal, rbPython;
    private EditText etCustomPort, etCustomIp, etTgIp, etUpstreamAddr, etRelayUrl;
    private CheckBox cbDynamicPort, cbAutostart, cbUpstreamProxy, cbRelay;
    private RadioGroup rgUpstreamType;
    private RadioButton rbUpstreamSocks5, rbUpstreamHttp;
    private Handler handler;
    private Runnable statsUpdater;
    private SharedPreferences prefs;
    private volatile boolean pingRunning = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Показываем версию в заголовке
        try {
            String ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            TextView tvTitle = findViewById(R.id.tv_title);
            tvTitle.setText("TG Proxy v" + ver);
        } catch (Exception ignored) {}

        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        handler = new Handler(Looper.getMainLooper());

        btnStart = findViewById(R.id.btn_start);
        btnStop = findViewById(R.id.btn_stop);
        tvStatus = findViewById(R.id.tv_status);
        tvAddress = findViewById(R.id.tv_address);
        tvPort = findViewById(R.id.tv_port);
        tvTgLink = findViewById(R.id.tv_tg_link);
        tvPing = findViewById(R.id.tv_ping);
        tvTraffic = findViewById(R.id.tv_traffic);
        tvUptime = findViewById(R.id.tv_uptime);
        rgMode = findViewById(R.id.rg_mode);
        rbOriginal = findViewById(R.id.rb_original);
        rbPython = findViewById(R.id.rb_python);
        cbDynamicPort = findViewById(R.id.cb_dynamic_port);
        cbAutostart = findViewById(R.id.cb_autostart);
        etCustomPort = findViewById(R.id.et_custom_port);
        etCustomIp = findViewById(R.id.et_custom_ip);
        etTgIp = findViewById(R.id.et_tg_ip);
        cbUpstreamProxy = findViewById(R.id.cb_upstream_proxy);
        rgUpstreamType = findViewById(R.id.rg_upstream_type);
        rbUpstreamSocks5 = findViewById(R.id.rb_upstream_socks5);
        rbUpstreamHttp = findViewById(R.id.rb_upstream_http);
        etUpstreamAddr = findViewById(R.id.et_upstream_addr);
        cbRelay = findViewById(R.id.cb_relay);
        etRelayUrl = findViewById(R.id.et_relay_url);

        int savedMode = prefs.getInt("proxy_mode", ProxyEngine.MODE_ORIGINAL);
        if (savedMode == ProxyEngine.MODE_PYTHON) {
            rbPython.setChecked(true);
        } else {
            rbOriginal.setChecked(true);
        }

        cbDynamicPort.setChecked(prefs.getBoolean("dynamic_port", false));
        cbAutostart.setChecked(prefs.getBoolean("autostart_open", false));

        // Upstream proxy settings
        cbUpstreamProxy.setChecked(prefs.getBoolean("upstream_enabled", false));
        String savedUpstreamType = prefs.getString("upstream_type", "socks5");
        if ("http".equals(savedUpstreamType)) {
            rbUpstreamHttp.setChecked(true);
        } else {
            rbUpstreamSocks5.setChecked(true);
        }
        etUpstreamAddr.setText(prefs.getString("upstream_addr", ""));

        // Relay settings
        cbRelay.setChecked(prefs.getBoolean("relay_enabled", false));
        etRelayUrl.setText(prefs.getString("relay_url", ""));

        int savedPort = prefs.getInt("custom_port", 1080);
        etCustomPort.setText(String.valueOf(savedPort));

        String savedIp = prefs.getString("custom_ip", "127.0.0.1");
        etCustomIp.setText(savedIp);

        String savedTgIp = prefs.getString("tg_ping_ip", "149.154.167.220");
        etTgIp.setText(savedTgIp);

        rgMode.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rb_python) {
                saveMode(ProxyEngine.MODE_PYTHON);
            } else {
                saveMode(ProxyEngine.MODE_ORIGINAL);
            }
        });

        cbDynamicPort.setOnCheckedChangeListener((v, c) ->
                prefs.edit().putBoolean("dynamic_port", c).apply());
        cbAutostart.setOnCheckedChangeListener((v, c) ->
                prefs.edit().putBoolean("autostart_open", c).apply());

        // Применяем relay и upstream proxy при запуске приложения
        applyRelay();
        applyUpstreamProxy();

        btnStart.setOnClickListener(v -> startProxy());
        btnStop.setOnClickListener(v -> stopProxy());

        setupCopyOnTap(tvAddress);
        setupCopyOnTap(tvPort);
        setupTgLinkTap(tvTgLink);
        setupCopyOnTap(tvPing);
        setupCopyOnTap(tvTraffic);

        requestPermissions();
        requestBatteryOptimization();

        statsUpdater = new Runnable() {
            @Override
            public void run() {
                updateStats();
                handler.postDelayed(this, 2000);
            }
        };

        if (ProxyService.getInstance() != null) {
            updateRunningState(true);
        }

        boolean autoOpen = prefs.getBoolean("autostart_open", false);
        if (autoOpen && ProxyService.getInstance() == null) {
            startProxy();
        }

        TextView tvTgChannel = findViewById(R.id.tv_tg_channel);
        TextView tvGithub = findViewById(R.id.tv_github);
        tvTgChannel.setOnClickListener(v -> openLink("https://t.me/jar_with_neurons"));
        tvGithub.setOnClickListener(v -> openLink("https://github.com/nonlxyzsg-dev/TelegramUnlockAppAndroid2026"));

        Button btnLogs = findViewById(R.id.btn_logs);
        btnLogs.setOnClickListener(v -> {
            startActivity(new Intent(this, LogActivity.class));
        });

        TextView tvDiagResult = findViewById(R.id.tv_diag_result);
        Button btnDiagnose = findViewById(R.id.btn_diagnose);
        Button btnCopyDiag = findViewById(R.id.btn_copy_diag);

        btnDiagnose.setOnClickListener(v -> {
            btnDiagnose.setEnabled(false);
            tvDiagResult.setText("\u23F3 \u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430...");
            tvDiagResult.setTextColor(0xFFAAAA00);

            ProxyService svc = ProxyService.getInstance();
            String proxyIp = svc != null ? svc.getIp() : "127.0.0.1";
            int proxyPort = svc != null ? svc.getPort() : 1080;

            DiagnosticsUtil.runFullDiagnostics(this, proxyIp, proxyPort, result -> {
                handler.post(() -> {
                    tvDiagResult.setText(result.summary);
                    tvDiagResult.setTextColor(0xFFE0E0E0);
                    btnDiagnose.setEnabled(true);
                });
            });
        });

        btnCopyDiag.setOnClickListener(v -> {
            String text = tvDiagResult.getText().toString();
            if (text.isEmpty() || text.startsWith("\u041d\u0430\u0436\u043c\u0438\u0442\u0435") || text.startsWith("\u23F3")) {
                Toast.makeText(this, "\u0421\u043d\u0430\u0447\u0430\u043b\u0430 \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0443", Toast.LENGTH_SHORT).show();
                return;
            }
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("diagnostics", text));
            Toast.makeText(this, "\u0414\u0438\u0430\u0433\u043d\u043e\u0441\u0442\u0438\u043a\u0430 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d\u0430", Toast.LENGTH_SHORT).show();
        });
    }

    private void openLink(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)));
        } catch (Exception ignored) {
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(statsUpdater);
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(statsUpdater);
    }

    private void startProxy() {
        saveSettings();

        Intent si = new Intent(this, ProxyService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(si);
        } else {
            startService(si);
        }

        handler.postDelayed(() -> updateRunningState(true), 500);
    }

    private void stopProxy() {
        stopService(new Intent(this, ProxyService.class));
        updateRunningState(false);
    }

    private void saveSettings() {
        SharedPreferences.Editor e = prefs.edit();
        if (rbOriginal.isChecked()) e.putInt("proxy_mode", ProxyEngine.MODE_ORIGINAL);
        else if (rbPython.isChecked()) e.putInt("proxy_mode", ProxyEngine.MODE_PYTHON);

        String portStr = etCustomPort.getText().toString().trim();
        int port = 1080;
        try {
            port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) port = 1080;
        } catch (NumberFormatException ignored) {
        }
        e.putInt("custom_port", port);

        String ip = etCustomIp.getText().toString().trim();
        if (ip.isEmpty()) ip = "127.0.0.1";
        e.putString("custom_ip", ip);

        String tgIp = etTgIp.getText().toString().trim();
        if (tgIp.isEmpty()) tgIp = "149.154.167.220";
        e.putString("tg_ping_ip", tgIp);

        // Upstream proxy
        boolean upstreamEnabled = cbUpstreamProxy.isChecked();
        e.putBoolean("upstream_enabled", upstreamEnabled);
        e.putString("upstream_type", rbUpstreamHttp.isChecked() ? "http" : "socks5");
        String upstreamAddr = etUpstreamAddr.getText().toString().trim();
        e.putString("upstream_addr", upstreamAddr);

        // Relay
        e.putBoolean("relay_enabled", cbRelay.isChecked());
        e.putString("relay_url", etRelayUrl.getText().toString().trim());

        e.apply();

        // Применяем настройки
        applyUpstreamProxy();
        applyRelay();
    }

    private void applyUpstreamProxy() {
        boolean enabled = cbUpstreamProxy.isChecked();
        String addr = etUpstreamAddr.getText().toString().trim();
        if (enabled && !addr.isEmpty() && addr.contains(":")) {
            String[] parts = addr.split(":", 2);
            String host = parts[0].trim();
            int port = 1080;
            try { port = Integer.parseInt(parts[1].trim()); } catch (NumberFormatException ignored) {}
            int type = rbUpstreamHttp.isChecked() ? RawWebSocket.PROXY_HTTP : RawWebSocket.PROXY_SOCKS5;
            RawWebSocket.setUpstreamProxy(type, host, port);
        } else {
            RawWebSocket.setUpstreamProxy(RawWebSocket.PROXY_NONE, null, 0);
        }
    }

    private void applyRelay() {
        boolean enabled = cbRelay.isChecked();
        String url = etRelayUrl.getText().toString().trim();
        if (enabled && !url.isEmpty()) {
            RawWebSocket.setRelayUrl(url);
        } else {
            RawWebSocket.setRelayUrl(null);
        }
    }

    private void saveMode(int mode) {
        prefs.edit().putInt("proxy_mode", mode).apply();
    }

    private android.animation.ObjectAnimator pulseAnim;

    private void updateRunningState(boolean running) {
        if (running) {
            btnStart.setEnabled(false);
            btnStop.setEnabled(true);
            tvStatus.setText("\u2705 \u0410\u043a\u0442\u0438\u0432\u0435\u043d");
            tvStatus.setTextColor(0xFF4CAF50);

            if (pulseAnim == null) {
                android.animation.PropertyValuesHolder sx = android.animation.PropertyValuesHolder.ofFloat("scaleX", 1f, 1.1f);
                android.animation.PropertyValuesHolder sy = android.animation.PropertyValuesHolder.ofFloat("scaleY", 1f, 1.1f);
                pulseAnim = android.animation.ObjectAnimator.ofPropertyValuesHolder(tvStatus, sx, sy);
                pulseAnim.setDuration(700);
                pulseAnim.setRepeatCount(android.animation.ValueAnimator.INFINITE);
                pulseAnim.setRepeatMode(android.animation.ValueAnimator.REVERSE);
            }
            pulseAnim.start();

            ProxyService svc = ProxyService.getInstance();
            int p = svc != null ? svc.getPort() : 1080;
            String ip = svc != null ? svc.getIp() : "127.0.0.1";
            tvAddress.setText(ip + ":" + p);
            tvPort.setText(String.valueOf(p));
            tvTgLink.setText("tg://socks?server=" + ip + "&port=" + p);
        } else {
            btnStart.setEnabled(true);
            btnStop.setEnabled(false);
            if (pulseAnim != null) pulseAnim.cancel();
            tvStatus.setScaleX(1f);
            tvStatus.setScaleY(1f);
            tvStatus.setAlpha(1f);
            tvStatus.setText("\u274C \u041e\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d");
            tvStatus.setTextColor(0xFFF44336);
            tvAddress.setText("-");
            tvPort.setText("-");
            tvTgLink.setText("-");
            tvPing.setText("-");
            tvTraffic.setText("-");
            if (tvUptime != null) tvUptime.setText("-");
        }
    }

    private void updateStats() {
        ProxyService svc = ProxyService.getInstance();
        if (svc == null || svc.getEngine() == null) return;

        int p = svc.getPort();
        String ip = svc.getIp();
        if (!tvPort.getText().toString().equals("-") && !tvAddress.getText().toString().equals(ip + ":" + p)) {
            tvAddress.setText(ip + ":" + p);
            tvPort.setText(String.valueOf(p));
            tvTgLink.setText("tg://socks?server=" + ip + "&port=" + p);
        }

        ProxyEngine eng = svc.getEngine();
        long up = eng.bytesUp.get();
        long down = eng.bytesDown.get();
        tvTraffic.setText("\u2191 " + TgConstants.humanBytes(up) +
                "  \u2193 " + TgConstants.humanBytes(down));

        if (tvUptime != null) {
            long secs = svc.getUptime() / 1000;
            String timeStr = String.format(java.util.Locale.US, "%02d:%02d:%02d", secs / 3600, (secs % 3600) / 60, secs % 60);
            tvUptime.setText(timeStr);
        }

        svc.updateNotification(svc.getIp() + ":" + svc.getPort() +
                " | \u2191" + TgConstants.humanBytes(up) +
                " \u2193" + TgConstants.humanBytes(down));

        if (!pingRunning) {
            pingRunning = true;
            new Thread(() -> {
                try {
                    // Тестируем WS handshake напрямую к Telegram DC — это реальный тест,
                    // а не TCP-пинг который проходит через DPI
                    String tgIp = prefs.getString("tg_ping_ip", "149.154.167.220");

                    // Определяем DC по IP
                    int dc = 2; // по умолчанию
                    for (java.util.Map.Entry<Integer, String> entry : TgConstants.DC_IPS.entrySet()) {
                        if (entry.getValue().equals(tgIp)) {
                            dc = entry.getKey();
                            break;
                        }
                    }
                    String domain = "kws" + dc + ".web.telegram.org";

                    long[] result = DiagnosticsUtil.testWsHandshake(tgIp, domain, 8000);
                    long wsPing = result[0];
                    int wsStatus = (int) result[1];

                    if (wsStatus == 101) {
                        handler.post(() -> tvPing.setText(wsPing + " ms (WS)"));
                    } else if (wsPing >= 0) {
                        // TCP проходит но WS не работает — DPI
                        long tcpPing = DiagnosticsUtil.testTcpConnect(tgIp, 443, 3000);
                        handler.post(() -> tvPing.setText("DPI! TCP:" + tcpPing + "ms WS:❌"));
                    } else {
                        handler.post(() -> tvPing.setText("❌ недоступен"));
                    }
                } catch (Exception e) {
                    handler.post(() -> tvPing.setText("err"));
                } finally {
                    pingRunning = false;
                }
            }).start();
        }
    }

    private void setupTgLinkTap(TextView tv) {
        tv.setOnClickListener(v -> {
            String text = tv.getText().toString();
            if (text.equals("-")) return;
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(text)));
            } catch (Exception e) {
                ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("proxy", text));
                Toast.makeText(this, "\u0421\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d\u043e", Toast.LENGTH_SHORT).show();
            }
        });
        tv.setOnLongClickListener(v -> {
            String text = tv.getText().toString();
            if (text.equals("-")) return false;
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("proxy", text));
            Toast.makeText(this, "\u0421\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d\u043e", Toast.LENGTH_SHORT).show();
            return true;
        });
    }

    private void setupCopyOnTap(TextView tv) {
        tv.setOnClickListener(v -> {
            String text = tv.getText().toString();
            if (text.equals("-")) return;
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("proxy", text));
            Toast.makeText(this, "\u0421\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d\u043e", Toast.LENGTH_SHORT).show();
        });
    }

    private void requestPermissions() {
        if (Build.VERSION.SDK_INT >= 33) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
            }
        }
    }

    private void requestBatteryOptimization() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (!pm.isIgnoringBatteryOptimizations(getPackageName())) {
                Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                intent.setData(Uri.parse("package:" + getPackageName()));
                try {
                    startActivity(intent);
                } catch (Exception ignored) {
                }
            }
        }
    }
}
