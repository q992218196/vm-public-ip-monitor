<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>告警 #{{ $alert->id }} · VM 流量监控</title>
    <style>
        body{margin:0;background:#f4f7fa;color:#173047;font:15px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
        main{max-width:1060px;margin:0 auto;padding:28px 20px 64px}
        a{color:#0f766e;text-decoration:none}a:hover{text-decoration:underline}
        .card{background:#fff;border:1px solid #e1e8ed;border-radius:16px;padding:22px;margin-top:18px;box-shadow:0 12px 32px -26px #173047}
        h1{font-size:1.7rem;line-height:1.3;margin:16px 0}h2{font-size:1.1rem;margin:0 0 14px}
        dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:0}dt{color:#64748b;font-size:.85rem}dd{margin:2px 0 0;font-weight:600;overflow-wrap:anywhere}
        .badge{display:inline-block;padding:2px 10px;border-radius:999px;background:#fee2e2;color:#b91c1c}.badge.acknowledged{background:#fef3c7;color:#92400e}.badge.resolved{background:#dcfce7;color:#15803d}
        pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#102334;color:#e5f6f2;padding:18px;border-radius:12px;max-height:65vh;overflow:auto;font-size:13px}
        ul{padding-left:1.3rem}li{overflow-wrap:anywhere}
        @media(max-width:600px){main{padding:16px 12px 40px}.card{padding:16px}h1{font-size:1.35rem}}
    </style>
</head>
<body>
<main>
    <a href="{{ url('/admin/alerts') }}">← 返回告警中心</a>
    <h1>{{ $alert->title }}</h1>
    <span class="badge {{ $alert->status }}">#{{ $alert->id }} · {{ \App\Support\Labels::get($alert->status) }}</span>
    <section class="card">
        <h2>基本信息</h2>
        <dl>
            <div><dt>公网 IP</dt><dd>{{ $alert->ipAsset?->ip ?? '—' }}</dd></div>
            <div><dt>观察节点</dt><dd>{{ $alert->node?->name ?? '—' }}</dd></div>
            <div><dt>级别</dt><dd>{{ \App\Support\Labels::get($alert->severity) }}</dd></div>
            <div><dt>类型</dt><dd>{{ \App\Support\Labels::get($alert->kind) }}</dd></div>
            <div><dt>触发次数</dt><dd>{{ $alert->occurrences }}</dd></div>
            <div><dt>最后触发</dt><dd>{{ $alert->last_seen_at?->timezone(config('monitor.display_timezone'))?->format('Y-m-d H:i:s') }}</dd></div>
        </dl>
    </section>
    @if ($alert->kind === 'capture_degraded')
        <section class="card"><h2>采集覆盖说明</h2>
            <p>这表示 Agent 在该采集窗口内出现丢包或丢弃状态，窗口数据可能不完整；它不是 VM 发起异常流量的证据。</p>
            <dl>
                <div><dt>内核丢包</dt><dd>{{ $alert->evidence['kernel_drops'] ?? 0 }}</dd></div>
                <div><dt>内存状态丢弃</dt><dd>{{ $alert->evidence['state_dropped'] ?? 0 }}</dd></div>
                <div><dt>本地队列丢弃</dt><dd>{{ $alert->evidence['spool_dropped'] ?? 0 }}</dd></div>
            </dl>
            <p>请检查节点采集接口、Agent 资源上限和磁盘空间。计数恢复为零后，后续窗口才可视为恢复覆盖。</p>
        </section>
    @endif
    @if (! empty($alert->evidence['sample']['ports'] ?? []))
        <section class="card"><h2>观测到的目标端口（最多 64 项）</h2><p>{{ implode('、', $alert->evidence['sample']['ports']) }}</p>@if ($alert->evidence['sample']['port_samples_truncated'] ?? false)<p>端口样本已截断，完整目标数请参考原始证据。</p>@endif</section>
    @endif
    @if (! empty($alert->evidence['sample']['target_endpoints'] ?? []))
        <section class="card"><h2>目标地址与端口（最多 32 项）</h2><ul>@foreach ($alert->evidence['sample']['target_endpoints'] as $endpoint)<li>{{ $endpoint }}</li>@endforeach</ul>@if ($alert->evidence['sample']['endpoint_samples_truncated'] ?? false)<p>地址样本已截断。</p>@endif</section>
    @endif
    @if ($alert->kind === 'vpn_protocol')
        <section class="card"><h2>协议握手证据</h2><dl>
            <div><dt>匹配协议</dt><dd>{{ \App\Support\Labels::get($alert->evidence['protocol'] ?? null) }}</dd></div>
            <div><dt>对端 IP</dt><dd>{{ $alert->evidence['peer_ip'] ?? '—' }}</dd></div>
            <div><dt>本机／对端端口</dt><dd>{{ $alert->evidence['local_port'] ?? '—' }} / {{ $alert->evidence['peer_port'] ?? '—' }}</dd></div>
            <div><dt>握手发起方</dt><dd>{{ ($alert->evidence['initiator'] ?? '') === 'vm' ? 'VM' : '对端' }}</dd></div>
            <div><dt>请求／响应数量</dt><dd>{{ $alert->evidence['request_count'] ?? 0 }} / {{ $alert->evidence['response_count'] ?? 0 }}</dd></div>
            <div><dt>请求／响应长度</dt><dd>{{ $alert->evidence['request_length'] ?? 0 }} / {{ $alert->evidence['response_length'] ?? 0 }} 字节</dd></div>
            <div><dt>请求／响应报文头</dt><dd>{{ $alert->evidence['request_header'] ?? '—' }} / {{ $alert->evidence['response_header'] ?? '—' }}</dd></div>
        </dl>
        @if ($alert->evidence['observation_id'] ?? null) <p><a href="{{ route('protocol-observations.evidence', $alert->evidence['observation_id']) }}">下载该窗口的独立 JSON 证据</a></p> @endif
        <p>被动识别结果不能证明隧道建立、认证成功、VM 内具体进程或用途违规；请结合业务授权和其他日志核查。</p></section>
    @endif
    @if ($alert->kind === 'proxy_suspect')
        <section class="card"><h2>疑似加密代理流量线索</h2><dl>
            <div><dt>外层传输</dt><dd>{{ \App\Support\Labels::get($alert->evidence['transport'] ?? null) }}</dd></div>
            <div><dt>VM 服务端口</dt><dd>{{ $alert->evidence['local_port'] ?? '—' }}</dd></div>
            <div><dt>不同对端／双向会话</dt><dd>{{ $alert->evidence['peer_count'] ?? 0 }} / {{ $alert->evidence['session_count'] ?? 0 }}</dd></div>
            <div><dt>接收／发送载荷</dt><dd>{{ $alert->evidence['bytes_from_peers'] ?? 0 }} / {{ $alert->evidence['bytes_to_peers'] ?? 0 }} 字节</dd></div>
            <div><dt>VM 主动发起 TCP 的出站目标数</dt><dd>{{ $alert->evidence['egress_target_count'] ?? 0 }}</dd></div>
        </dl>
        <p>对端样本：{{ implode('、', $alert->evidence['peer_samples'] ?? []) }}</p>
        <p>出站目标样本：{{ implode('、', $alert->evidence['egress_target_samples'] ?? []) }}</p>
        <p>可能兼容的协议：{{ implode('、', $alert->evidence['candidate_protocols'] ?? []) }}。这些名称不是识别结论。</p>
        @if ($alert->evidence['observation_id'] ?? null) <p><a href="{{ route('protocol-observations.evidence', $alert->evidence['observation_id']) }}">下载该窗口的独立 JSON 证据</a></p> @endif
        <p>仅为行为相关性线索，不能确认 SS、SSR、VMess、Trojan、Hysteria、VLESS 或 AnyTLS；普通加密业务可能有相同外观，须人工复核。</p></section>
    @endif
    <section class="card"><h2>原始证据</h2><pre>{{ json_encode($alert->evidence, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) }}</pre></section>
    @if ($alert->resolution)
        <section class="card"><h2>处理记录</h2><p>{{ $alert->resolution }}</p></section>
    @endif
</main>
</body>
</html>
