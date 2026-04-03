package com.tgproxy.app;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class LogActivity extends AppCompatActivity {

    private TextView tvLog;
    private ScrollView scrollView;
    private boolean autoScroll = true;
    private Handler handler;
    private int pendingLines = 0;
    private static final int LOG_BATCH_DELAY = 300; // мс — обновляем UI не чаще

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Корневой layout: кнопки сверху (фиксированные) + ScrollView с логами снизу
        android.widget.LinearLayout mainLayout = new android.widget.LinearLayout(this);
        mainLayout.setOrientation(android.widget.LinearLayout.VERTICAL);
        mainLayout.setBackgroundColor(0xFF0A0A0A);

        // Кнопки — фиксированные сверху
        android.widget.LinearLayout btnRow = new android.widget.LinearLayout(this);
        btnRow.setOrientation(android.widget.LinearLayout.HORIZONTAL);
        btnRow.setPadding(16, 8, 16, 8);
        btnRow.setBackgroundColor(0xFF1A1A1A);

        Button btnCopy = new Button(this);
        btnCopy.setText("Копировать");
        btnCopy.setTextSize(13);
        btnCopy.setAllCaps(false);
        android.widget.LinearLayout.LayoutParams btnLp = new android.widget.LinearLayout.LayoutParams(
                0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        btnLp.setMargins(0, 0, 8, 0);
        btnRow.addView(btnCopy, btnLp);

        Button btnClear = new Button(this);
        btnClear.setText("Очистить");
        btnClear.setTextSize(13);
        btnClear.setAllCaps(false);
        android.widget.LinearLayout.LayoutParams btnLp2 = new android.widget.LinearLayout.LayoutParams(
                0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        btnLp2.setMargins(8, 0, 8, 0);
        btnRow.addView(btnClear, btnLp2);

        Button btnRefresh = new Button(this);
        btnRefresh.setText("Обновить");
        btnRefresh.setTextSize(13);
        btnRefresh.setAllCaps(false);
        android.widget.LinearLayout.LayoutParams btnLp3 = new android.widget.LinearLayout.LayoutParams(
                0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        btnLp3.setMargins(8, 0, 0, 0);
        btnRow.addView(btnRefresh, btnLp3);

        // Кнопки не скроллятся — фиксированы сверху
        mainLayout.addView(btnRow, new android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT));

        // ScrollView с логами — занимает оставшееся место
        ScrollView sv = new ScrollView(this);
        sv.setFillViewport(true);

        tvLog = new TextView(this);
        tvLog.setTextColor(0xFF00FF00);
        tvLog.setTextSize(11);
        tvLog.setTypeface(android.graphics.Typeface.MONOSPACE);
        tvLog.setPadding(16, 8, 16, 8);
        tvLog.setTextIsSelectable(true);
        sv.addView(tvLog);

        scrollView = sv;
        mainLayout.addView(sv, new android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));

        setContentView(mainLayout);

        handler = new Handler(Looper.getMainLooper());

        // Заголовок
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle("Логи TGProxy");
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        // Загрузить текущие логи
        refreshLog();

        // Подписка на новые логи — батчим обновления UI
        AppLog.setListener(line -> {
            pendingLines++;
            handler.removeCallbacks(batchUpdate);
            if (pendingLines >= 50) {
                // Много строк — обновляем сразу (но не чаще чем раз в 300мс)
                handler.post(batchUpdate);
            } else {
                handler.postDelayed(batchUpdate, LOG_BATCH_DELAY);
            }
        });

        btnCopy.setOnClickListener(v -> {
            String logs = AppLog.getAll();
            if (logs.isEmpty()) {
                Toast.makeText(this, "Логи пусты", Toast.LENGTH_SHORT).show();
                return;
            }
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("TGProxy Logs", logs));
            Toast.makeText(this, "Логи скопированы (" + AppLog.size() + " строк)", Toast.LENGTH_SHORT).show();
        });

        btnClear.setOnClickListener(v -> {
            AppLog.clear();
            tvLog.setText("");
            Toast.makeText(this, "Логи очищены", Toast.LENGTH_SHORT).show();
        });

        btnRefresh.setOnClickListener(v -> refreshLog());
    }

    private final Runnable batchUpdate = () -> {
        pendingLines = 0;
        refreshLog();
    };

    private void refreshLog() {
        String logs = AppLog.getAll();
        tvLog.setText(logs.isEmpty() ? "Логов пока нет. Запустите прокси." : logs);
        if (autoScroll) {
            scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        handler.removeCallbacks(batchUpdate);
        AppLog.setListener(null);
    }

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }
}
