package com.livecam.mobile

import android.content.Intent
import android.os.Build
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

class BroadcastServicePlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel
    private var context: android.content.Context? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "com.livecam.mobile/broadcast_service")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        context = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        val ctx = context ?: run {
            result.error("NO_CONTEXT", "No context", null)
            return
        }
        when (call.method) {
            "start" -> {
                val title = call.argument<String>("title") ?: "livecam"
                val body = call.argument<String>("body") ?: "Live"
                val intent = Intent(ctx, BroadcastForegroundService::class.java).apply {
                    putExtra(BroadcastForegroundService.EXTRA_TITLE, title)
                    putExtra(BroadcastForegroundService.EXTRA_BODY, body)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ctx.startForegroundService(intent)
                } else {
                    ctx.startService(intent)
                }
                result.success(null)
            }
            "stop" -> {
                ctx.stopService(Intent(ctx, BroadcastForegroundService::class.java))
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }
}
