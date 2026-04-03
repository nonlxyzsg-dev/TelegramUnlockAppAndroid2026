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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(0xFF0A0A0A);
        sv.setFillViewport(true);

        android.widget.LinearLayout root = new android.widget.LinearLayout(this);
        root.setOrientation(android.widget.LinearLayout.VERTICAL);
        root.setPadding(16, 16, 16, 16);

        // Кнопки
        android.widget.LinearLayout btnRow = new android.widget.LinearLayout(this);
        btnRow.setOrientation(android.widget.LinearLayout.HORIZONTAL);

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
        btnLp2.setMargins(8, 0, 0, 0);
        btnRow.addView(btnClear, btnLp2);

        Button btnRefresh = new Button(this);
        btnRefresh.setText("Обновить");
        btnRefresh.setTextSize(13);
        btnRefresh.setAllCaps(false);
        android.widget.LinearLayout.LayoutParams btnLp3 = new android.widget.LinearLayout.LayoutParams(
                0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        btnLp3.setMargins(8, 0, 0, 0);
        btnRow.addView(btnRefresh, btnLp3);

        root.addView(btnRow);

        // Текст логов
        tvLog = new TextView(this);
        tvLog.setTextColor(0xFF00FF00);
        tvLog.setTextSize(11);
        tvLog.setTypeface(android.graphics.Typeface.MONOSPACE);
        tvLog.setPadding(0, 16, 0, 16);
        tvLog.setTextIsSelectable(true);
        root.addView(tvLog);

        sv.addView(root);
        scrollView = sv;
        setContentView(sv);

        handler = new Handler(Looper.getMainLooper());

        // Заголовок
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle("Логи TGProxy");
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        // Загрузить текущие логи
        refreshLog();

        // Подписка на новые логи
        AppLog.setListener(line -> handler.post(() -> {
            tvLog.append(line + "\n");
            if (autoScroll) {
                scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
            }
        }));

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

    private void refreshLog() {
        String logs = AppLog.getAll();
        tvLog.setText(logs.isEmpty() ? "Логов пока нет. Запустите прокси." : logs);
        scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        AppLog.setListener(null);
    }

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }
}
