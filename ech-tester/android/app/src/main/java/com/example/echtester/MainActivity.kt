package com.example.echtester

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import echtester.Echtester
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var targetInput: EditText
    private lateinit var sourceInput: EditText
    private lateinit var publicNameInput: EditText
    private lateinit var sniInput: EditText
    private lateinit var dohInput: EditText
    private lateinit var ipInput: EditText
    private lateinit var runButton: Button
    private lateinit var logView: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildContent())
        restoreValues()
    }

    private fun buildContent(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
        }
        val header = TextView(this).apply {
            text = "ECH 握手测试"
            textSize = 22f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(0xff17202a.toInt())
        }
        root.addView(header, matchWrap())
        root.addView(TextView(this).apply {
            text = "读取一个域名的 ECH 配置，并测试它能否用于另一个域名"
            textSize = 13f
            setTextColor(0xff5f6368.toInt())
        }, matchWrap(bottom = 8))

        targetInput = addField(root, "目标域名", "example.com 或 example.com:443")
        sourceInput = addField(root, "ECH 配置来源域名", "留空则使用目标域名")
        publicNameInput = addField(root, "public_name", "留空则使用配置中的值")
        sniInput = addField(root, "sni（内层 SNI）", "留空则使用目标域名")
        dohInput = addField(root, "DoH 地址", "https://cloudflare-dns.com/dns-query")
        ipInput = addField(root, "连接 IP（可选）", "多个 IP 用逗号分隔")

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        runButton = Button(this).apply {
            text = "开始握手"
            setOnClickListener { startTest() }
        }
        actions.addView(runButton, weight(1f, end = 6))
        actions.addView(Button(this).apply {
            text = "复制日志"
            setOnClickListener { copyLog() }
        }, weight(1f, start = 6))
        root.addView(actions, matchWrap(top = 4))

        val clearButton = Button(this).apply {
            text = "清空日志"
            setOnClickListener { logView.setText("") }
        }
        root.addView(clearButton, matchWrap(top = 2, bottom = 4))

        logView = EditText(this).apply {
            setTextIsSelectable(true)
            setTextSize(12f)
            typeface = Typeface.MONOSPACE
            gravity = Gravity.TOP or Gravity.START
            isVerticalScrollBarEnabled = true
            setHorizontallyScrolling(false)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            setHint("握手日志")
            setPadding(dp(10), dp(10), dp(10), dp(10))
            setBackgroundColor(0xfff1f3f4.toInt())
        }
        val logScroll = ScrollView(this).apply {
            isFillViewport = true
            addView(logView, matchWrap())
        }
        root.addView(logScroll, LinearLayout.LayoutParams(-1, 0, 1f))
        return root
    }

    private fun addField(parent: LinearLayout, label: String, hint: String): EditText {
        parent.addView(TextView(this).apply {
            text = label
            textSize = 13f
            setTextColor(0xff3c4043.toInt())
        }, matchWrap(top = 4))
        return EditText(this).also { input ->
            input.hint = hint
            input.singleLine = true
            input.textSize = 14f
            input.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            parent.addView(input, matchWrap())
        }
    }

    private fun startTest() {
        val target = targetInput.text.toString().trim()
        if (target.isEmpty()) {
            targetInput.error = "请输入目标域名"
            return
        }
        saveValues()
        runButton.isEnabled = false
        appendLog("\n--- ${now()} 开始 ---\n")
        val args = listOf(
            target,
            sourceInput.text.toString().trim(),
            publicNameInput.text.toString().trim(),
            sniInput.text.toString().trim(),
            dohInput.text.toString().trim(),
            ipInput.text.toString().trim(),
        )
        executor.execute {
            val result = try {
                Echtester.test(args[0], args[1], args[2], args[3], args[4], args[5])
            } catch (error: Throwable) {
                "RESULT=FAIL\nAndroid native error: ${error.message ?: error}\n"
            }
            runOnUiThread {
                appendLog(result)
                runButton.isEnabled = true
            }
        }
    }

    private fun appendLog(text: String) {
        logView.append(text)
        logView.post { logView.setSelection(logView.text.length) }
    }

    private fun copyLog() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("ECH handshake log", logView.text))
        Toast.makeText(this, "日志已复制", Toast.LENGTH_SHORT).show()
    }

    private fun restoreValues() {
        val prefs = getPreferences(Context.MODE_PRIVATE)
        targetInput.setText(prefs.getString("target", ""))
        sourceInput.setText(prefs.getString("source", ""))
        publicNameInput.setText(prefs.getString("public", ""))
        sniInput.setText(prefs.getString("sni", ""))
        dohInput.setText(prefs.getString("doh", "https://cloudflare-dns.com/dns-query"))
        ipInput.setText(prefs.getString("ips", ""))
    }

    private fun saveValues() {
        getPreferences(Context.MODE_PRIVATE).edit()
            .putString("target", targetInput.text.toString())
            .putString("source", sourceInput.text.toString())
            .putString("public", publicNameInput.text.toString())
            .putString("sni", sniInput.text.toString())
            .putString("doh", dohInput.text.toString())
            .putString("ips", ipInput.text.toString())
            .apply()
    }

    private fun now(): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
    private fun matchWrap(top: Int = 0, bottom: Int = 0): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, dp(top), 0, dp(bottom)) }
    private fun weight(value: Float, start: Int = 0, end: Int = 0): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(0, -2, value).apply { setMargins(dp(start), 0, dp(end), 0) }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
