<x-filament-panels::page>
    @php
        $link = function (array $changes) use ($filters): string {
            $query = array_merge(\Illuminate\Support\Arr::except($filters, ['cursor']), $changes);
            $query = array_filter($query, fn ($value) => $value !== null && $value !== '');
            return url()->current() . ($query ? '?' . http_build_query($query) : '');
        };
    @endphp
    <div class="monitor-fast-list">
        <div class="monitor-list-intro">轻量分页仅传输当前行的显示字段。查看详情时单独读取该条证据。</div>
        @if (session('status')) <div class="monitor-notice">{{ session('status') }}</div> @endif
        @if ($errors->any()) <div class="monitor-error">{{ $errors->first() }}</div> @endif
        <div class="monitor-list-toolbar">
            <details class="monitor-menu"><summary>节点：{{ $nodes->firstWhere('id', $filters['node'] ?? null)?->name ?? '全部' }}</summary><div class="monitor-menu-items">
                <a href="{{ $link(['node' => null]) }}">全部节点</a>
                @foreach ($nodes as $node) <a href="{{ $link(['node' => $node->id]) }}">{{ $node->name }}</a> @endforeach
            </div></details>
            <details class="monitor-menu"><summary>级别：{{ \App\Support\Labels::get($filters['severity'] ?? '') ?: '全部' }}</summary><div class="monitor-menu-items">
                <a href="{{ $link(['severity' => null]) }}">全部级别</a>
                @foreach (['high' => '高', 'medium' => '中', 'low' => '低'] as $key => $label) <a href="{{ $link(['severity' => $key]) }}">{{ $label }}</a> @endforeach
            </div></details>
            <details class="monitor-menu"><summary>状态：{{ \App\Support\Labels::get($filters['status'] ?? '') ?: '全部' }}</summary><div class="monitor-menu-items">
                <a href="{{ $link(['status' => null]) }}">全部状态</a>
                @foreach (['open' => '待处理', 'acknowledged' => '已确认', 'resolved' => '已解决'] as $key => $label) <a href="{{ $link(['status' => $key]) }}">{{ $label }}</a> @endforeach
            </div></details>
            <form method="get" action="{{ url()->current() }}" class="monitor-inline-search">
                @foreach (\Illuminate\Support\Arr::except($filters, ['ip', 'cursor']) as $key => $value) <input type="hidden" name="{{ $key }}" value="{{ $value }}"> @endforeach
                <input name="ip" value="{{ $filters['ip'] ?? '' }}" placeholder="完整公网 IP" aria-label="完整公网 IP">
                <button type="submit">查询</button>
            </form>
            <details class="monitor-menu"><summary>每页 {{ $perPage }} 条</summary><div class="monitor-menu-items">
                @foreach ([10, 25, 50, 100, 200, 500] as $size) <a href="{{ $link(['per_page' => $size]) }}">{{ $size }} 条</a> @endforeach
            </div></details>
            <a class="monitor-outline" href="{{ route('exports', 'alerts') }}">导出告警</a>
        </div>
        @if (auth()->user()?->role === 'admin') <form method="post" action="{{ route('alerts.bulk') }}"> @endif
            @if (auth()->user()?->role === 'admin')
            @csrf
            <div class="monitor-list-toolbar monitor-bulk-toolbar">
                <strong>批量处理所选告警（最多 500 条）</strong>
                <input name="resolution" maxlength="4000" required placeholder="填写处理记录" aria-label="处理记录">
                <button name="status" value="acknowledged" type="submit">标记已确认</button>
                <button name="status" value="resolved" type="submit">标记已解决</button>
                <button name="status" value="open" type="submit" class="monitor-outline">重新打开</button>
            </div>
            @endif
            <div class="monitor-table-wrap"><table class="monitor-fast-table">
                <thead><tr>@if (auth()->user()?->role === 'admin') <th><input type="checkbox" aria-label="选择本页全部告警" onchange="document.querySelectorAll('[data-alert-id]').forEach(el => el.checked = this.checked)"></th> @endif<th>告警</th><th>公网 IP</th><th>观察节点</th><th>级别</th><th>状态</th><th>次数</th><th>最后触发</th><th>操作</th></tr></thead>
                <tbody>
                    @forelse ($alerts as $alert)
                        <tr>
                            @if (auth()->user()?->role === 'admin') <td><input data-alert-id type="checkbox" name="ids[]" value="{{ $alert->id }}" aria-label="选择告警 {{ $alert->id }}"></td> @endif
                            <td>{{ $alert->title }}</td>
                            <td>{{ $alert->ipAsset?->ip ?? '—' }}</td>
                            <td>{{ $alert->node?->name ?? '—' }}</td>
                            <td><span class="monitor-badge {{ $alert->severity }}">{{ \App\Support\Labels::get($alert->severity) }}</span></td>
                            <td><span class="monitor-badge {{ $alert->status }}">{{ \App\Support\Labels::get($alert->status) }}</span></td>
                            <td>{{ $alert->occurrences }}</td>
                            <td>{{ $alert->last_seen_at?->timezone(config('monitor.display_timezone'))?->format('Y-m-d H:i:s') }}</td>
                            <td><a href="{{ route('alerts.evidence', $alert) }}" target="_blank" rel="noopener">详情</a></td>
                        </tr>
                    @empty <tr><td colspan="{{ auth()->user()?->role === 'admin' ? 9 : 8 }}">没有匹配的告警</td></tr> @endforelse
                </tbody>
            </table></div>
        @if (auth()->user()?->role === 'admin') </form> @endif
        <nav class="monitor-cursor-nav" aria-label="告警分页">
            @if ($alerts->previousPageUrl()) <a href="{{ $alerts->previousPageUrl() }}">← 上一页</a> @endif
            <span>本页 {{ $alerts->count() }} 条 · <span data-monitor-alert-total data-count-url="{{ route('alerts.count', \Illuminate\Support\Arr::only($filters, ['node', 'ip', 'severity', 'status'])) }}" role="status">总计：统计中…</span></span>
            @if ($alerts->nextPageUrl()) <a href="{{ $alerts->nextPageUrl() }}">下一页 →</a> @endif
        </nav>
    </div>
</x-filament-panels::page>
