webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new Bridge(), "bridge");
settings.setAllowUniversalAccessFromFileURLs(true);
SharedPreferences p = getSharedPreferences("auth", MODE_WORLD_READABLE);
