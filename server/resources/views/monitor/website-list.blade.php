<x-filament-panels::page>
    @php
        $link = function (array $changes) use ($filters): string {
            $query = array_merge(\Illuminate\Support\Arr::except($filters, ['cursor']), $changes);
            $query = array_filter($query, fn ($value) => $value !== null && $value !== '');
            return url()->current() . ($query ? '?' . http_build_query($query) : '');
        };
    @endphp
    <div class="monitor-fast-list">
        <div class="monitor-list-intro">网站线索以轻量分页展示；验证、截图与完整记录按需读取。</div>
        @if (session('status')) <div class="monitor-notice">{{ session('status') }}</div> @endif
        @if ($errors->any()) <div class="monitor-error">{{ $errors->first() }}</div> @endif
        <div class="monitor-list-toolbar">
            <form method="get" action="{{ url()->current() }}" class="monitor-inline-search">
                @foreach (\Illuminate\Support\Arr::except($filters, ['ip', 'host', 'cursor']) as $key => $value) <input type="hidden" name="{{ $key }}" value="{{ $value }}"> @endforeach
                <input name="ip" value="{{ $filters['ip'] ?? '' }}" placeholder="完整公网 IP" aria-label="完整公网 IP">
                <input name="host" value="{{ $filters['host'] ?? '' }}" placeholder="域名前缀" aria-label="域名前缀">
                <button type="submit">查询</button>
            </form>
            <details class="monitor-menu"><summary>状态：{{ \App\Support\Labels::get($filters['status'] ?? '') ?: '全部' }}</summary><div class="monitor-menu-items">
                <a href="{{ $link(['status' => null]) }}">全部状态</a>
                @foreach (['observed' => '待验证线索', 'candidate' => '探测候选', 'verified' => '已验证', 'failed' => '失败'] as $key => $label) <a href="{{ $link(['status' => $key]) }}">{{ $label }}</a> @endforeach
            </div></details>
            <a class="monitor-outline" href="{{ $link(['review' => isset($filters['review']) ? null : '1']) }}">{{ isset($filters['review']) ? '显示全部' : '待人工复核' }}</a>
            <a class="monitor-outline" href="{{ $link(['show_description' => isset($filters['show_description']) ? null : '1']) }}">{{ isset($filters['show_description']) ? '隐藏描述' : '显示描述' }}</a>
            <details class="monitor-menu"><summary>每页 {{ $perPage }} 条</summary><div class="monitor-menu-items">
                @foreach ([10, 25, 50, 100, 200, 500] as $size) <a href="{{ $link(['per_page' => $size]) }}">{{ $size }} 条</a> @endforeach
            </div></details>
            <a class="monitor-outline" href="{{ route('exports', 'websites') }}">导出网站</a>
        </div>
        @if (auth()->user()?->role === 'admin')
            <details class="monitor-create"><summary>添加已知 IP 网站</summary>
                <form method="post" action="{{ route('websites.manual') }}" class="monitor-list-toolbar">@csrf
                    <input name="ip" required placeholder="已发现的公网 IP" aria-label="已发现的公网 IP">
                    <input name="port" required type="number" min="1" max="65535" placeholder="端口" aria-label="端口">
                    <label><input name="scheme" type="radio" value="http" checked> HTTP</label>
                    <label><input name="scheme" type="radio" value="https"> HTTPS</label>
                    <input name="host" placeholder="域名，可留空" aria-label="域名">
                    <button type="submit">加入验证队列</button>
                </form>
            </details>
        @endif
        <div class="monitor-table-wrap"><table class="monitor-fast-table">
            <thead><tr><th>公网 IP</th><th>域名线索</th><th>端口</th><th>协议</th><th>状态</th><th>标题</th>@if (isset($filters['show_description'])) <th>网站描述</th> @endif<th>分类</th><th>最近验证</th><th>操作</th></tr></thead>
            <tbody>
                @forelse ($websites as $site)
                    <tr>
                        <td>{{ $site->ipAsset?->ip ?? '—' }}</td>
                        <td>@if ($site->publicUrl()) <a href="{{ $site->publicUrl() }}" target="_blank" rel="noopener" title="域名 DNS 可能指向其他 IP">{{ $site->host }}</a>@else {{ $site->host ?: '仅 IP' }} @endif</td>
                        <td>{{ $site->port }}</td><td>{{ strtoupper($site->scheme) }}</td>
                        <td><span class="monitor-badge {{ $site->status }}">{{ \App\Support\Labels::get($site->status) }}</span></td>
                        <td>{{ \Illuminate\Support\Str::limit($site->title, 40) }}</td>
                        @if (isset($filters['show_description'])) <td>{{ \Illuminate\Support\Str::limit($site->description, 100) }}</td> @endif
                        <td>{{ $site->manual_category ?: ($site->category ?? '—') }}</td>
                        <td>{{ $site->last_probed_at?->timezone(config('monitor.display_timezone'))?->format('Y-m-d H:i') ?? '—' }}</td>
                        <td class="monitor-row-actions">
                            <a href="{{ route('websites.details', $site) }}" target="_blank" rel="noopener">详情</a>
                            @if ($site->screenshot_path) <a href="{{ route('screenshots.show', $site) }}" target="_blank" rel="noopener">截图</a> @endif
                            @if (auth()->user()?->role === 'admin') <form method="post" action="{{ route('websites.probe', $site) }}">@csrf<button type="submit">验证</button></form> @endif
                        </td>
                    </tr>
                @empty <tr><td colspan="{{ isset($filters['show_description']) ? 10 : 9 }}">没有匹配的网站</td></tr> @endforelse
            </tbody>
        </table></div>
        <nav class="monitor-cursor-nav" aria-label="网站分页">
            @if ($websites->previousPageUrl()) <a href="{{ $websites->previousPageUrl() }}">← 上一页</a> @endif
            <span>本页 {{ $websites->count() }} 条</span>
            @if ($websites->nextPageUrl()) <a href="{{ $websites->nextPageUrl() }}">下一页 →</a> @endif
        </nav>
    </div>
</x-filament-panels::page>
