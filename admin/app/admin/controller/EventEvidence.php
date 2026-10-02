<?php

namespace app\admin\controller;

use app\common\service\EventReviewReport;

class EventEvidence extends Monitor
{
    private function query()
    {
        $q = $this->db()->table('monitor_events')->alias('e')->leftJoin('ip_assets i', 'i.id=e.ip_asset_id')->leftJoin('nodes n', 'n.id=e.node_id');
        foreach (['status', 'severity', 'node_id', 'assessment_category'] as $key) {
            $value = (string) $this->request->get($key, '');
            if ($value !== '') {
                $q->where('e.'.$key, $value);
            }
        }
        $ip = (string) $this->request->get('ip', '');
        if ($ip !== '') {
            $q->where('i.ip', $ip);
        }
        $search = mb_substr((string) $this->request->get('search', ''), 0, 100);
        if ($search !== '') {
            $q->whereLike('e.title', '%'.$search.'%');
        }

        return $q;
    }

    public function index(): void
    {
        $sort = match ((string) $this->request->get('sort')) {
            'ip' => 'i.ip', 'title' => 'e.title', 'severity' => 'e.severity', 'status' => 'e.status', 'occurrences' => 'e.occurrences', default => 'e.last_seen_at',
        };
        $rows = $this->query()->field('e.id,e.title,e.severity,e.status,e.assessment_category,e.kinds,e.occurrences,e.first_seen_at,e.last_seen_at,i.ip,n.name AS node_name')
            ->order($sort, $this->request->get('direction') === 'asc' ? 'asc' : 'desc')->order('e.id', 'desc')->page(max(1, (int) $this->request->get('page', 1)), max(10, min(500, (int) $this->request->get('limit', 25))))->select()->toArray();
        foreach ($rows as &$row) {
            $row['kinds'] = $this->decode($row['kinds']);
        }
        $this->success('', ['list' => $rows, 'super' => $this->auth->isSuperAdmin()]);
    }

    public function count(): void
    {
        $this->success('', ['total' => (int) $this->query()->count()]);
    }

    public function detail(): void
    {
        $id = (int) $this->request->get('id');
        $event = $this->db()->table('monitor_events')->alias('e')->leftJoin('ip_assets i', 'i.id=e.ip_asset_id')->leftJoin('nodes n', 'n.id=e.node_id')->field('e.*,i.ip,n.name AS node_name,n.health AS node_health')->where('e.id', $id)->find();
        if (! $event) {
            $this->error('事件不存在', [], 404);
        }
        foreach (['kinds', 'quality', 'node_health', 'behavior', 'review_context'] as $key) {
            $event[$key] = $this->decode($event[$key]);
        }
        unset($event['active_key']);
        $ids = $this->db()->table('alerts')->where('event_id', $id)->group('kind')->column('MAX(id) AS id');
        $alerts = $ids ? $this->db()->table('alerts')->whereIn('id', $ids)->field('id,title,kind,severity,status,evidence,first_seen_at,last_seen_at')->select()->toArray() : [];
        foreach ($alerts as &$alert) {
            $alert['evidence'] = $this->decode($alert['evidence']);
        }
        $progress = $this->progressData($id);
        $settings = $this->db()->table('ai_settings')->where('id', 1)->field('endpoint,model,enabled')->find();
        $this->success('', ['event' => $event, 'alerts' => $alerts, 'ai' => $settings] + $progress);
    }

    private function progressData(int $id): array
    {
        $captures = $this->db()->table('packet_captures')->where('event_id', $id)->field('id,status,source,ip,bytes,sha256,snaplen,metadata,last_error,created_at,updated_at')->order('created_at', 'desc')->limit(20)->select()->toArray();
        foreach ($captures as &$capture) {
            $capture['metadata'] = $this->decode($capture['metadata']);
        }
        $analyses = $this->db()->table('ai_analyses')->where('event_id', $id)->field('id,capture_id,status,last_error,created_at,finished_at')->order('id', 'desc')->limit(20)->select()->toArray();

        return ['captures' => $captures, 'analyses' => $analyses];
    }

    public function progress(): void
    {
        $id = (int) $this->request->get('id');
        if (! $this->db()->table('monitor_events')->where('id', $id)->find()) {
            $this->error('事件不存在', [], 404);
        }
        $this->success('', $this->progressData($id));
    }

    public function reviewReport(): void
    {
        $id = (int) $this->request->get('id');
        $event = $this->db()->table('monitor_events')->alias('e')->leftJoin('ip_assets i', 'i.id=e.ip_asset_id')->leftJoin('nodes n', 'n.id=e.node_id')->field('e.*,i.ip,n.name AS node_name')->where('e.id', $id)->find();
        if (! $event) {
            $this->error('事件不存在', [], 404);
        }
        $ids = $this->db()->table('alerts')->where('event_id', $id)->group('kind')->column('MAX(id) AS id');
        $alerts = $ids ? $this->db()->table('alerts')->whereIn('id', $ids)->field('kind,title,severity,status,evidence,last_seen_at')->limit(20)->select()->toArray() : [];
        $metrics = [];
        if ($event['ip_asset_id']) {
            $cutoff = max(strtotime($event['first_seen_at'].' UTC'), strtotime($event['last_seen_at'].' UTC') - 3600);
            $metrics = $this->db()->table('traffic_metrics')->where('node_id', $event['node_id'])->where('ip_asset_id', $event['ip_asset_id'])
                ->where('window_end', '>=', gmdate('Y-m-d H:i:s', $cutoff))->where('window_end', '<=', $event['last_seen_at'])
                ->field('window_start,window_end,tcp_attempts,bytes_in,bytes_out,evidence')->order('window_end', 'desc')->limit(121)->select()->toArray();
        }
        $this->success('', ['report' => EventReviewReport::build($event, $alerts, $metrics)]);
    }

    public function review(): void
    {
        $this->writable();
        $ids = array_values(array_unique(array_map('intval', $this->request->post('ids/a', []))));
        $status = (string) $this->request->post('status');
        $notes = mb_substr((string) $this->request->post('notes', ''), 0, 2000);
        if (! $ids || count($ids) > 500 || ! in_array($status, ['open', 'acknowledged', 'normal', 'resolved'], true)) {
            $this->error('处理参数无效');
        }
        if (in_array($status, ['normal', 'resolved'], true) && trim($notes) === '') {
            $this->error('请填写业务核查依据或处理说明');
        }
        $this->db()->transaction(function () use ($ids, $status, $notes) {
            $events = $this->db()->table('monitor_events')->whereIn('id', $ids)->order('id')->lock(true)->select()->toArray();
            foreach ($events as $event) {
                $data = ['status' => $status, 'review_notes' => $notes, 'reopen_reason' => null, 'updated_at' => gmdate('Y-m-d H:i:s')];
                if (in_array($status, ['normal', 'resolved'], true)) {
                    $data['review_context'] = $event['behavior'] ?: '{}';
                }
                $this->db()->table('monitor_events')->where('id', $event['id'])->update($data);
            }
            $this->db()->table('alerts')->whereIn('event_id', $ids)->update(['status' => in_array($status, ['normal', 'resolved'], true) ? 'resolved' : $status, 'resolution' => $notes, 'updated_at' => gmdate('Y-m-d H:i:s')]);
            $this->audit('events.reviewed', 'MonitorEvent', ['ids' => $ids, 'status' => $status]);
        });
        $this->success('已记录审核结果');
    }

    public function whitelist(): void
    {
        $this->writable();
        $id = (int) $this->request->post('id');
        $this->db()->transaction(function () use ($id) {
            $event = $this->db()->table('monitor_events')->where('id', $id)->find();
            if (! $event) {
                $this->error('事件不存在', [], 404);
            }
            $this->db()->table('nodes')->where('id', $event['node_id'])->lock(true)->find();
            $event = $this->db()->table('monitor_events')->where('id', $id)->lock(true)->find();
            if (in_array('capture_degraded', $this->decode($event['kinds']), true)) {
                $this->error('采集覆盖下降属于采集质量问题，不支持加入白名单；请处理丢包或采集限额。');
            }
            $ip = $event['ip_asset_id'] ? $this->db()->table('ip_assets')->where('id', $event['ip_asset_id'])->value('ip') : null;
            if ($event['ip_asset_id'] && ! $ip) {
                $this->error('IP 资产不存在');
            }
            $cidr = $ip ? $ip.(str_contains($ip, ':') ? '/128' : '/32') : null;
            $now = gmdate('Y-m-d H:i:s');
            foreach ($this->decode($event['kinds']) as $kind) {
                $scope = ['node_id' => $event['node_id'], 'cidr' => $cidr, 'kind' => $kind];
                $existing = $this->db()->table('exclusions')->where($scope)->find();
                $values = ['expires_at' => gmdate('Y-m-d H:i:s', time() + 30 * 86400), 'updated_at' => $now];
                if ($existing) {
                    $this->db()->table('exclusions')->where('id', $existing['id'])->update($values);
                } else {
                    $this->db()->table('exclusions')->insert($scope + $values + ['reason' => '管理员审核事件 #'.$id, 'created_at' => $now]);
                }
            }
            $this->db()->table('monitor_events')->where('id', $id)->update(['status' => 'normal', 'review_context' => $event['behavior'] ?: '{}', 'reopen_reason' => null, 'review_notes' => '当前节点、IP、已命中类型加入 30 天白名单', 'updated_at' => $now]);
            $this->db()->table('alerts')->where('event_id', $id)->update(['status' => 'resolved', 'resolution' => '事件已加入 30 天白名单', 'updated_at' => $now]);
            $this->audit('event.whitelisted', 'MonitorEvent:'.$id, ['ip' => $ip, 'kinds' => $this->decode($event['kinds'])]);
        });
        $this->success('已加入 30 天白名单；原始证据保留');
    }

    public function capture(): void
    {
        $this->writable();
        $id = (int) $this->request->post('id');
        $snaplen = (int) $this->request->post('snaplen', 2048);
        $captureId = '';
        if (! in_array($snaplen, [2048, 65535], true)) {
            $this->error('抓包长度无效');
        }
        $this->db()->transaction(function () use ($id, $snaplen, &$captureId) {
            $event = $this->db()->table('monitor_events')->where('id', $id)->find();
            if (! $event || ! $event['ip_asset_id']) {
                $this->error('此事件没有可抓包的公网 IP');
            }
            $node = $this->db()->table('nodes')->where('id', $event['node_id'])->lock(true)->find();
            $health = $this->decode($node['health']);
            if (! $node['enabled'] || version_compare($health['version'] ?? '0', '0.6.0', '<')) {
                $this->error('节点须启用并升级到 Agent 0.6.0 或以上');
            }
            $ip = $this->db()->table('ip_assets')->where('id', $event['ip_asset_id'])->value('ip');
            $tasks = $this->db()->table('packet_captures')->where('node_id', $node['id']);
            if ((clone $tasks)->whereIn('status', ['pending', 'leased'])->count() >= 10 || (clone $tasks)->where('ip', $ip)->where('created_at', '>', gmdate('Y-m-d H:i:s', time() - 1800))->whereIn('status', ['pending', 'leased', 'uploaded'])->find()) {
                $this->error('该 IP 已有最近 30 分钟的采集任务，或节点等待队列已满');
            }
            $b = random_bytes(16);
            $b[6] = chr((ord($b[6]) & 15) | 64);
            $b[8] = chr((ord($b[8]) & 63) | 128);
            $h = bin2hex($b);
            $captureId = substr($h, 0, 8).'-'.substr($h, 8, 4).'-'.substr($h, 12, 4).'-'.substr($h, 16, 4).'-'.substr($h, 20);
            $now = gmdate('Y-m-d H:i:s');
            $this->db()->table('packet_captures')->insert(['id' => $captureId, 'event_id' => $id, 'node_id' => $node['id'], 'ip' => $ip, 'snaplen' => $snaplen, 'source' => 'manual', 'created_at' => $now, 'updated_at' => $now]);
            $this->audit('capture.requested', 'MonitorEvent:'.$id, ['capture_id' => $captureId, 'snaplen' => $snaplen]);
        });
        $this->success('已申请未来 60 秒抓包，上限 32 MiB', ['id' => $captureId]);
    }

    public function download()
    {
        $this->writable();
        $id = (string) $this->request->get('id');
        $capture = $this->db()->table('packet_captures')->where('id', $id)->find();
        if (! $capture || $capture['status'] !== 'uploaded' || $capture['path'] !== 'packet-evidence/'.$id.'.pcap') {
            $this->error('PCAP 不存在或已过期', [], 404);
        }
        $path = '/monitor-storage/app/private/'.$capture['path'];
        if (! is_file($path)) {
            $this->error('PCAP 文件不可用', [], 404);
        }
        $this->audit('capture.downloaded', 'PacketCapture:'.$id, ['sha256' => $capture['sha256']]);

        return download($path, $id.'.pcap')->header(['Cache-Control' => 'no-store', 'X-Content-Type-Options' => 'nosniff']);
    }

    public function settings(): void
    {
        $this->writable();
        $row = $this->db()->table('ai_settings')->where('id', 1)->find();
        $this->success('', ['endpoint' => $row['endpoint'] ?? 'https://api.deepseek.com/chat/completions', 'model' => $row['model'] ?? 'deepseek-flash', 'enabled' => (bool) ($row['enabled'] ?? false), 'key_configured' => ! empty($row['api_key_cipher'])]);
    }

    public function captureSummary(): void
    {
        $row = $this->db()->table('packet_captures')->where('id', (string) $this->request->get('id'))->field('id,status,sha256,summary,metadata,last_error')->find();
        if (! $row) {
            $this->error('抓包记录不存在', [], 404);
        }
        $row['summary'] = $this->decode($row['summary']);
        $row['metadata'] = $this->decode($row['metadata']);
        $this->success('', ['record' => $row]);
    }

    public function saveSettings(): void
    {
        $this->writable();
        $endpoint = (string) $this->request->post('endpoint');
        $model = (string) $this->request->post('model');
        $enabled = (bool) $this->request->post('enabled');
        $key = trim((string) $this->request->post('api_key', ''));
        if (! in_array($endpoint, ['https://api.deepseek.com/chat/completions', 'https://api.deepseek.com/v1/chat/completions'], true) || ! preg_match('/^[a-zA-Z0-9._-]{1,80}$/', $model)) {
            $this->error('DeepSeek 接口地址或模型无效');
        }
        if ($key !== '' && ! preg_match('/^[\x21-\x7e]{16,512}$/', $key)) {
            $this->error('API Key 格式无效');
        }
        $row = $this->db()->table('ai_settings')->where('id', 1)->find();
        $cipher = $row['api_key_cipher'] ?? null;
        if ($key !== '') {
            $secret = getenv('MONITOR_SECRET_KEY') ?: '';
            $raw = str_starts_with($secret, 'base64:') ? base64_decode(substr($secret, 7), true) : $secret;
            if (! $raw || strlen($raw) < 32) {
                $this->error('主控未配置共享加密密钥，请按新版部署教程更新');
            }
            $nonce = random_bytes(12);
            $tag = '';
            $encrypted = openssl_encrypt($key, 'aes-256-gcm', hash('sha256', $raw, true), OPENSSL_RAW_DATA, $nonce, $tag, 'vm-monitor-ai-v1');
            if ($encrypted === false) {
                $this->error('无法加密 API Key');
            }
            $cipher = base64_encode($nonce.$tag.$encrypted);
        }
        if ($enabled && ! $cipher) {
            $this->error('请先填写 API Key');
        }
        $now = gmdate('Y-m-d H:i:s');
        $data = ['endpoint' => $endpoint, 'model' => $model, 'enabled' => $enabled, 'api_key_cipher' => $cipher, 'updated_at' => $now];
        if ($row) {
            $this->db()->table('ai_settings')->where('id', 1)->update($data);
        } else {
            $this->db()->table('ai_settings')->insert(['id' => 1, 'created_at' => $now] + $data);
        }
        $this->audit('ai.settings_saved', 'AiSettings', ['endpoint' => $endpoint, 'model' => $model, 'enabled' => $enabled]);
        $this->success('已保存；不会调用 AI');
    }

    public function requestAi(): void
    {
        $this->writable();
        $captureId = (string) $this->request->post('capture_id');
        $mode = (string) $this->request->post('evidence_mode', 'summary');
        if (! in_array($mode, ['summary', 'full_packets'], true)) {
            $this->error('证据发送模式无效');
        }
        $analysisId = 0;
        $this->db()->transaction(function () use ($captureId, $mode, &$analysisId) {
            $capture = $this->db()->table('packet_captures')->where('id', $captureId)->lock(true)->find();
            if (! $capture || $capture['status'] !== 'uploaded') {
                $this->error('请先完成抓包');
            }
            $settings = $this->db()->table('ai_settings')->where('id', 1)->find();
            if (! $settings || ! $settings['enabled'] || ! $settings['api_key_cipher']) {
                $this->error('请先配置并启用 AI');
            }
            if ($this->db()->table('ai_analyses')->where('capture_id', $captureId)->whereIn('status', ['pending', 'running'])->find()) {
                $this->error('此 PCAP 已有等待或执行中的分析');
            }
            $now = gmdate('Y-m-d H:i:s');
            $analysisId = $this->db()->table('ai_analyses')->insertGetId(['event_id' => $capture['event_id'], 'capture_id' => $captureId, 'requested_by' => $this->auth->id, 'config_snapshot' => json_encode(array_intersect_key($settings, array_flip(['endpoint', 'model', 'api_key_cipher'])) + ['evidence_mode' => $mode]), 'created_at' => $now, 'updated_at' => $now]);
            $this->audit('ai.manually_requested', 'AiAnalysis:'.$analysisId, ['capture_id' => $captureId, 'sha256' => $capture['sha256'], 'model' => $settings['model'], 'payload' => 'parsed text evidence only', 'evidence_mode' => $mode]);
        });
        $this->success('已申请 AI 分析；不会自动重试或改变审核结果', ['id' => $analysisId]);
    }

    public function analysis(): void
    {
        $row = $this->db()->table('ai_analyses')->where('id', (int) $this->request->get('id'))->field('id,event_id,capture_id,requested_by,status,config_snapshot,evidence,report,usage,last_error,created_at,finished_at')->find();
        if (! $row) {
            $this->error('分析记录不存在', [], 404);
        }
        $config = $this->decode($row['config_snapshot']);
        unset($row['config_snapshot']);
        $row['model'] = $config['model'] ?? null;
        $row['endpoint'] = $config['endpoint'] ?? null;
        $row['evidence_mode'] = $config['evidence_mode'] ?? 'summary';
        $row['evidence'] = $this->decode($row['evidence']);
        $row['usage'] = $this->decode($row['usage']);
        $this->success('', ['record' => $row]);
    }
}
