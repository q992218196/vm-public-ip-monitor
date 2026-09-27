<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>网站 #{{ $website->id }} · VM 流量监控</title>
    <style>
        body{margin:0;background:#f4f7fa;color:#173047;font:15px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
        main{max-width:1060px;margin:0 auto;padding:28px 20px 64px}a{color:#0f766e;text-decoration:none}a:hover{text-decoration:underline}
        h1{font-size:1.7rem;line-height:1.3;margin:16px 0;overflow-wrap:anywhere}h2{font-size:1.1rem;margin:0 0 14px}
        .card{background:#fff;border:1px solid #e1e8ed;border-radius:16px;padding:22px;margin-top:18px;box-shadow:0 12px 32px -26px #173047}
        dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin:0}dt{color:#64748b;font-size:.85rem}dd{margin:2px 0 0;font-weight:600;overflow-wrap:anywhere}
        pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#102334;color:#e5f6f2;padding:18px;border-radius:12px;max-height:45vh;overflow:auto;font-size:13px}
        input,button{font:inherit;padding:8px 12px;border-radius:8px}input{border:1px solid #cbd5e1;max-width:100%}button{border:0;background:#0f766e;color:#fff;cursor:pointer}form{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px}
        .notice{padding:10px 14px;background:#dcfce7;color:#166534;border-radius:8px}
        @media(max-width:600px){main{padding:16px 12px 40px}.card{padding:16px}h1{font-size:1.35rem}}
    </style>
</head>
<body><main>
    <a href="{{ url('/admin/websites') }}">← 返回网站资产</a>
    <h1>{{ $website->host ?: $website->ipAsset?->ip }}:{{ $website->port }}</h1>
    @if (session('status')) <p class="notice">{{ session('status') }}</p> @endif
    @if ($errors->any()) <p>{{ $errors->first() }}</p> @endif
    <section class="card"><h2>网站与验证</h2><dl>
        <div><dt>公网 IP</dt><dd>{{ $website->ipAsset?->ip }}</dd></div>
        <div><dt>域名线索</dt><dd>{{ $website->host ?: '仅 IP' }}</dd></div>
        <div><dt>协议及端口</dt><dd>{{ strtoupper($website->scheme) }} / {{ $website->port }}</dd></div>
        <div><dt>线索来源</dt><dd>{{ \App\Support\Labels::get($website->source) }}</dd></div>
        <div><dt>验证状态</dt><dd>{{ \App\Support\Labels::get($website->status) }}</dd></div>
        <div><dt>HTTP 状态</dt><dd>{{ $website->http_status ?? '—' }}</dd></div>
        <div><dt>最近验证</dt><dd>{{ $website->last_probed_at?->timezone(config('monitor.display_timezone'))?->format('Y-m-d H:i:s') ?? '—' }}</dd></div>
        <div><dt>网页标题</dt><dd>{{ $website->title ?? '—' }}</dd></div>
    </dl>
    @if ($website->publicUrl()) <p><a href="{{ $website->publicUrl() }}" target="_blank" rel="noopener">按域名和端口访问 ↗</a> · 浏览器 DNS 可能指向其他 IP</p> @endif
    @if ($website->final_url) <p>验证时最终地址：{{ $website->final_url }}</p> @endif
    @if ($website->last_error) <p>最近错误：{{ $website->last_error }}</p> @endif
    @if ($website->screenshot_path) <p><a href="{{ route('screenshots.show', $website) }}" target="_blank" rel="noopener">查看截图 ↗</a></p> @endif
    @if (auth()->user()?->role === 'admin') <form method="post" action="{{ route('websites.probe', $website) }}">@csrf<button type="submit">重新验证／截图</button></form> @endif
    </section>
    <section class="card"><h2>网页描述与分类</h2>
        <p>{{ $website->description ?: '未发现 meta 描述' }}</p>
        <dl><div><dt>自动分类</dt><dd>{{ $website->category ?? '—' }}</dd></div><div><dt>人工分类</dt><dd>{{ $website->manual_category ?? '—' }}</dd></div><div><dt>内容哈希</dt><dd>{{ $website->content_hash ?? '—' }}</dd></div></dl>
        @if (auth()->user()?->role === 'admin') <form method="post" action="{{ route('websites.category', $website) }}">@csrf<input name="manual_category" value="{{ $website->manual_category }}" maxlength="64" placeholder="人工分类，可留空" aria-label="人工分类"><button type="submit">保存人工分类</button></form> @endif
        <pre>{{ json_encode($website->classification, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) }}</pre>
    </section>
</main></body></html>
