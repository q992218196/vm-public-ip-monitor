<?php

namespace app\admin\controller;

use app\common\controller\Backend;
use think\facade\Db;

class Monitor extends Backend
{
    protected array $noNeedPermission = ['*'];

    public function initialize(): void
    {
        parent::initialize();
        if (!$this->auth->isSuperAdmin() && !$this->auth->check('monitor', mode: 'name')) {
            $this->error('没有监控数据访问权限', [], 403);
        }
    }

    private const TABLES = [
        'nodes' => ['name', 'id', 'enabled', 'cidrs', 'last_seen_at', 'health'],
        'ips' => ['ip', 'id', 'version', 'label', 'first_seen_at', 'last_seen_at'],
        'websites' => ['id', 'ip_asset_id', 'host', 'port', 'scheme', 'status', 'title', 'description', 'category', 'manual_category', 'last_probed_at', 'last_seen_at'],
        'alerts' => ['id', 'node_id', 'ip_asset_id', 'title', 'kind', 'severity', 'status', 'occurrences', 'last_seen_at'],
        'rules' => ['id', 'name', 'kind', 'threshold', 'window_seconds', 'cooldown_seconds', 'severity', 'node_id', 'enabled'],
        'exclusions' => ['id', 'cidr', 'reason', 'node_id', 'expires_at'],
        'metrics' => ['id', 'node_id', 'ip_asset_id', 'bytes_out', 'bytes_in', 'tcp_attempts', 'window_start', 'window_end'],
        'tasks' => ['id', 'website_id', 'status', 'attempts', 'last_error', 'updated_at'],
        'protocols' => ['id', 'node_id', 'ip_asset_id', 'protocol', 'peer_ip', 'local_port', 'peer_port', 'window_end'],
        'audit' => ['id', 'action', 'subject', 'created_at'],
    ];

    private const DATABASE_TABLES = [
        'ips' => 'ip_assets', 'metrics' => 'traffic_metrics', 'tasks' => 'probe_tasks', 'audit' => 'audit_logs', 'protocols' => 'protocol_observations',
    ];

    private function table(string $resource): string
    {
        if (!isset(self::TABLES[$resource])) {
            $this->error('未知的管理资源', [], 404);
        }
        return self::DATABASE_TABLES[$resource] ?? $resource;
    }

    private function db()
    {
        return Db::connect('monitor');
    }

    private function writable(): void
    {
        if (!$this->auth->isSuperAdmin()) {
            $this->error('仅管理员可以修改监控配置', [], 403);
        }
    }

    private function audit(string $action, string $subject, array $details = []): void
    {
        $this->db()->table('audit_logs')->insert([
            'user_id' => null,
            'action' => $action,
            'subject' => $subject,
            'details' => json_encode(['buildadmin_id' => $this->auth->id] + $details, JSON_UNESCAPED_UNICODE),
            'created_at' => date('Y-m-d H:i:s'),
        ]);
    }

    public function overview(): void
    {
        $db = $this->db();
        $this->success('', [
            'nodes' => $db->table('nodes')->where('enabled', true)->where('last_seen_at', '>', date('Y-m-d H:i:s', time() - 300))->count(),
            'ips' => $db->table('ip_assets')->count(),
            'websites' => $db->table('websites')->count(),
            'alerts' => $db->table('alerts')->where('status', 'open')->count(),
            'batches' => $db->table('batches')->whereNull('processed_at')->count(),
        ]);
    }

    public function nodes(): void
    {
        $rows = $this->db()->table('nodes')->field('id,name')->order('name')->select()->toArray();
        $this->success('', ['list' => $rows, 'super' => $this->auth->isSuperAdmin()]);
    }

    public function index(): void
    {
        $resource = (string)$this->request->get('resource', '');
        $table = $this->table($resource);
        $page = max(1, (int)$this->request->get('page', 1));
        $limit = max(10, min(500, (int)$this->request->get('limit', 25)));
        $query = $this->db()->table($table)->alias('m');
        $fields = array_map(fn ($field) => 'm.' . $field, self::TABLES[$resource]);
        if (in_array($resource, ['alerts', 'websites', 'metrics', 'protocols'], true)) {
            $query->leftJoin('ip_assets i', 'i.id=m.ip_asset_id');
            $fields[] = 'i.ip AS ip';
        }
        if (in_array($resource, ['alerts', 'metrics', 'protocols'], true)) {
            $query->leftJoin('nodes n', 'n.id=m.node_id');
            $fields[] = 'n.name AS node_name';
        }
        if ($resource === 'tasks') {
            $query->leftJoin('websites w', 'w.id=m.website_id')->leftJoin('ip_assets i', 'i.id=w.ip_asset_id');
            array_push($fields, 'w.host AS host', 'w.port AS port', 'i.ip AS ip');
        }
        $this->applyFilters($query, $resource);
        $sort = in_array($resource, ['alerts', 'websites', 'ips', 'nodes'], true) ? 'm.last_seen_at' : 'm.id';
        $rows = $query->field($fields)->order($sort, 'desc')->order('m.id', 'desc')->page($page, $limit)->select()->toArray();
        foreach ($rows as &$row) {
            if ($resource === 'nodes') {
                $row['cidrs'] = $this->decode($row['cidrs'] ?? null);
                $row['health'] = $this->decode($row['health'] ?? null);
                $row['rss_mib'] = isset($row['health']['rss_bytes']) ? round($row['health']['rss_bytes'] / 1048576) : null;
                $row['kernel_drops'] = $row['health']['kernel_drops'] ?? null;
            }
        }
        unset($row);
        $this->success('', ['list' => $rows, 'super' => $this->auth->isSuperAdmin()]);
    }

    public function count(): void
    {
        $resource = (string)$this->request->get('resource', '');
        $query = $this->db()->table($this->table($resource))->alias('m');
        if (in_array($resource, ['alerts', 'websites', 'metrics', 'protocols'], true)) $query->leftJoin('ip_assets i', 'i.id=m.ip_asset_id');
        if ($resource === 'tasks') $query->leftJoin('websites w', 'w.id=m.website_id')->leftJoin('ip_assets i', 'i.id=w.ip_asset_id');
        $this->applyFilters($query, $resource);
        $this->success('', ['total' => (int)$query->count()]);
    }

    private function applyFilters($query, string $resource): void
    {
        $node = (string)$this->request->get('node', '');
        $ip = (string)$this->request->get('ip', '');
        $status = (string)$this->request->get('status', '');
        $severity = (string)$this->request->get('severity', '');
        $search = trim((string)$this->request->get('search', ''));
        $review = (string)$this->request->get('review', '');
        if ($node !== '' && in_array($resource, ['alerts', 'metrics', 'protocols', 'rules', 'exclusions'], true)) {
            $query->where('m.node_id', $node);
        }
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            if ($resource === 'ips') $query->where('m.ip', $ip);
            if (in_array($resource, ['alerts', 'websites', 'metrics', 'tasks', 'protocols'], true)) $query->where('i.ip', $ip);
        }
        if ($status !== '' && in_array($resource, ['alerts', 'websites', 'tasks'], true)) $query->where('m.status', $status);
        if ($severity !== '' && $resource === 'alerts') $query->where('m.severity', $severity);
        if ($resource === 'websites' && $review === '1') {
            $query->whereIn('m.category', ['疑似博彩', '疑似成人内容', '疑似诈骗引流', '支付平台线索', '贷款平台线索'])->whereNull('m.manual_category');
        }
        if ($search !== '') {
            $field = match ($resource) {
                'nodes', 'rules' => 'm.name', 'ips' => 'm.ip', 'websites' => 'm.host',
                'alerts' => 'm.title', 'exclusions' => 'm.cidr', 'tasks' => 'w.host', default => null,
            };
            if ($field) $query->where($field, 'like', '%' . addcslashes($search, '%_\\') . '%');
        }
    }

    private function decode($value)
    {
        return is_string($value) ? (json_decode($value, true) ?: []) : $value;
    }

    public function detail(): void
    {
        $resource = (string)$this->request->get('resource', '');
        $id = (string)$this->request->get('id', '');
        $row = $this->db()->table($this->table($resource))->where('id', $id)->find();
        if (!$row) $this->error('记录不存在', [], 404);
        unset($row['token_hash']);
        foreach ($row as &$value) {
            if (is_string($value) && (str_starts_with($value, '{') || str_starts_with($value, '['))) {
                $decoded = json_decode($value, true);
                if (is_array($decoded)) $value = $decoded;
            }
        }
        $this->success('', ['record' => $row]);
    }

    public function bulkAlerts(): void
    {
        $this->writable();
        $ids = $this->request->post('ids/a', []);
        $status = (string)$this->request->post('status', '');
        $resolution = trim((string)$this->request->post('resolution', ''));
        if (count($ids) < 1 || count($ids) > 500 || count(array_unique($ids)) !== count($ids) || !in_array($status, ['open', 'acknowledged', 'resolved'], true) || $resolution === '' || mb_strlen($resolution) > 4000) {
            $this->error('告警选择、状态或处理记录无效');
        }
        foreach ($ids as $id) if (!filter_var($id, FILTER_VALIDATE_INT)) $this->error('告警 ID 无效');
        $db = $this->db();
        $db->startTrans();
        try {
            if (count($db->table('alerts')->whereIn('id', $ids)->lock(true)->column('id')) !== count($ids)) $this->error('有告警已不存在');
            $db->table('alerts')->whereIn('id', $ids)->update(['status' => $status, 'resolution' => $resolution, 'updated_at' => date('Y-m-d H:i:s')]);
            $this->audit('alerts_bulk_handled', 'Alert:batch', ['ids' => $ids, 'status' => $status, 'resolution' => $resolution]);
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollback();
            throw $e;
        }
        $this->success(count($ids) . ' 条告警已更新');
    }

    public function save(): void
    {
        $this->writable();
        $resource = (string)$this->request->post('resource', '');
        $table = $this->table($resource);
        if (!in_array($resource, ['ips', 'websites', 'rules', 'exclusions', 'nodes'], true)) $this->error('该资源不可编辑');
        $id = (string)$this->request->post('id', '');
        $data = $this->request->post('data/a', []);
        $allowed = match ($resource) {
            'ips' => ['label', 'notes'], 'websites' => ['manual_category'],
            'rules' => ['name', 'kind', 'enabled', 'severity', 'threshold', 'window_seconds', 'cooldown_seconds', 'node_id'],
            'exclusions' => ['cidr', 'reason', 'expires_at', 'node_id'],
            'nodes' => ['name', 'enabled', 'cidrs', 'settings', 'notes'],
        };
        $data = array_intersect_key($data, array_flip($allowed));
        if (!$data) $this->error('没有可保存的字段');
        $this->validateRecord($resource, $data, $id === '');
        if (isset($data['cidrs'])) $data['cidrs'] = json_encode($data['cidrs']);
        if (isset($data['settings'])) $data['settings'] = json_encode($data['settings']);
        $data['updated_at'] = date('Y-m-d H:i:s');
        if ($id === '') {
            if (!in_array($resource, ['nodes', 'rules', 'exclusions'], true)) $this->error('该资源不可新增');
            if ($resource === 'nodes') $data['id'] = $id = $this->uuid();
            $data['created_at'] = $data['updated_at'];
            if ($resource === 'nodes') {
                $this->db()->table($table)->insert($data);
            } else {
                $id = (string)$this->db()->table($table)->insertGetId($data);
            }
        } else {
            if (!$this->db()->table($table)->where('id', $id)->find()) $this->error('记录不存在', [], 404);
            $this->db()->table($table)->where('id', $id)->update($data);
        }
        $this->audit('monitor_saved', ucfirst($resource) . ':' . $id, ['fields' => array_keys($data)]);
        $this->success('已保存', ['id' => $id]);
    }

    private function validateRecord(string $resource, array &$data, bool $creating): void
    {
        if ($resource === 'nodes') {
            if (isset($data['name']) && (trim($data['name']) === '' || mb_strlen($data['name']) > 100)) $this->error('节点名称无效');
            if ($creating && (empty($data['name']) || empty($data['cidrs']))) $this->error('节点名称和 CIDR 必填');
            if (isset($data['cidrs'])) {
                if (!is_array($data['cidrs']) || count($data['cidrs']) < 1 || count($data['cidrs']) > 256) $this->error('CIDR 列表无效');
                foreach ($data['cidrs'] as $cidr) if (!$this->validCidr((string)$cidr)) $this->error('CIDR 格式无效');
            }
        if (isset($data['settings'])) {
            if (!is_array($data['settings'])) $this->error('节点配置无效');
            foreach (['memory_soft_mib' => [128, 32768], 'memory_hard_mib' => [256, 65536], 'disk_limit_mib' => [640, 1048576]] as $key => [$min, $max]) {
                if (isset($data['settings'][$key]) && (!filter_var($data['settings'][$key], FILTER_VALIDATE_INT) || $data['settings'][$key] < $min || $data['settings'][$key] > $max)) $this->error('节点资源上限无效');
            }
            if (isset($data['settings']['interfaces'])) {
                if (!is_array($data['settings']['interfaces']) || count($data['settings']['interfaces']) < 1 || count($data['settings']['interfaces']) > 64) $this->error('采集接口配置无效');
                foreach ($data['settings']['interfaces'] as $interface) if (!is_string($interface) || !preg_match('/^[a-zA-Z0-9_.:-]{1,64}$/', $interface)) $this->error('采集接口名称无效');
            }
            if (isset($data['settings']['data_dir']) && !preg_match('#^/[a-zA-Z0-9/_-]+$#', (string)$data['settings']['data_dir'])) $this->error('Agent 数据目录无效');
            if (isset($data['settings']['memory_soft_mib'], $data['settings']['memory_hard_mib']) && (int)$data['settings']['memory_soft_mib'] > (int)$data['settings']['memory_hard_mib']) $this->error('工作内存不能超过服务硬限额');
        }
            if (isset($data['enabled'])) $data['enabled'] = (bool)$data['enabled'];
        }
        if ($resource === 'ips' && isset($data['label']) && mb_strlen((string)$data['label']) > 255) $this->error('标签过长');
        if ($resource === 'websites' && array_key_exists('manual_category', $data)) {
            if (mb_strlen((string)$data['manual_category']) > 64) $this->error('人工分类过长');
            $data['manual_category'] = trim((string)$data['manual_category']) ?: null;
        }
        if ($resource === 'rules') {
            if ($creating && (empty($data['name']) || empty($data['kind']) || empty($data['threshold']))) $this->error('规则名称、类型和阈值必填');
            if (isset($data['name']) && (trim((string)$data['name']) === '' || mb_strlen((string)$data['name']) > 255)) $this->error('规则名称无效');
            if (isset($data['kind']) && !in_array($data['kind'], ['horizontal_scan', 'vertical_scan', 'suspected_bruteforce', 'single_target_attempts', 'tcp_connection_burst', 'egress_mbps', 'vpn_protocol', 'proxy_suspect'], true)) $this->error('规则类型无效');
            if (isset($data['severity']) && !in_array($data['severity'], ['low', 'medium', 'high'], true)) $this->error('告警级别无效');
            foreach (['threshold', 'window_seconds', 'cooldown_seconds'] as $field) if (isset($data[$field]) && (!filter_var($data[$field], FILTER_VALIDATE_INT) || (int)$data[$field] < 1 || (int)$data[$field] > 1000000000)) $this->error('规则数值无效');
            if (isset($data['enabled'])) $data['enabled'] = (bool)$data['enabled'];
        }
        if ($resource === 'exclusions') {
            if ($creating && (empty($data['cidr']) || empty($data['reason']) || empty($data['expires_at']))) $this->error('白名单信息不完整');
            if (isset($data['cidr']) && !$this->validCidr((string)$data['cidr'])) $this->error('CIDR 格式无效');
            if (isset($data['reason']) && (trim((string)$data['reason']) === '' || mb_strlen((string)$data['reason']) > 255)) $this->error('原因无效');
            if (isset($data['expires_at']) && strtotime((string)$data['expires_at']) <= time()) $this->error('失效时间必须在未来');
        }
        if (isset($data['node_id']) && $data['node_id'] === '') $data['node_id'] = null;
        if (isset($data['node_id']) && $data['node_id'] !== null && !$this->db()->table('nodes')->where('id', $data['node_id'])->find()) $this->error('指定节点不存在');
    }

    private function validCidr(string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2 || !filter_var($parts[0], FILTER_VALIDATE_IP) || !ctype_digit($parts[1])) return false;
        $max = str_contains($parts[0], ':') ? 128 : 32;
        return (int)$parts[1] <= $max;
    }

    private function uuid(): string
    {
        $hex = bin2hex(random_bytes(16));
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-4' . substr($hex, 13, 3) . '-8' . substr($hex, 17, 3) . '-' . substr($hex, 20, 12);
    }

    public function nodeConfig(): void
    {
        $this->writable();
        if (!filter_var(getenv('MONITOR_PUBLIC_URL'), FILTER_VALIDATE_URL)) $this->error('请先配置管理端公开地址');
        $id = (string)$this->request->post('id', '');
        $node = $this->db()->table('nodes')->where('id', $id)->find();
        if (!$node) $this->error('节点不存在', [], 404);
        $token = bin2hex(random_bytes(32));
        $this->db()->table('nodes')->where('id', $id)->update(['token_hash' => hash('sha256', $token), 'updated_at' => date('Y-m-d H:i:s')]);
        $this->audit('token_rotated', 'Node:' . $id);
        $settings = $this->decode($node['settings'] ?? null) ?: [];
        $this->success('新配置已生成，旧凭据已撤销', ['config' => [
            'node_id' => $id, 'server_url' => rtrim((string)getenv('MONITOR_PUBLIC_URL'), '/'), 'token' => $token,
            'interfaces' => $settings['interfaces'] ?? ['monitor0'], 'cidrs' => $this->decode($node['cidrs']),
            'data_dir' => $settings['data_dir'] ?? '/home/vm-monitor', 'memory_soft_mib' => (int)($settings['memory_soft_mib'] ?? 2048),
            'memory_hard_mib' => (int)($settings['memory_hard_mib'] ?? 4096), 'disk_limit_mib' => (int)($settings['disk_limit_mib'] ?? 2048),
            'spool_limit_mib' => 512, 'capture_buffer_mib' => 16, 'flush_seconds' => 30,
            'max_ips' => 4096, 'max_flows' => 50000, 'max_reassembly' => 2048, 'max_sites' => 4096, 'allow_http_localhost' => false,
        ]]);
    }

    public function probe(): void
    {
        $this->writable();
        $id = (int)$this->request->post('id', 0);
        $this->queueProbe($id);
        $this->success('已加入验证队列');
    }

    private function queueProbe(int $id): void
    {
        if (!$this->db()->table('websites')->where('id', $id)->find()) $this->error('网站不存在', [], 404);
        $now = date('Y-m-d H:i:s');
        $task = $this->db()->table('probe_tasks')->where('website_id', $id)->find();
        if (!$task) {
            $this->db()->table('probe_tasks')->insert(['website_id' => $id, 'status' => 'pending', 'attempts' => 0, 'available_at' => $now, 'created_at' => $now, 'updated_at' => $now]);
        } elseif (!in_array($task['status'], ['pending', 'leased'], true)) {
            $this->db()->table('probe_tasks')->where('website_id', $id)->update(['status' => 'pending', 'attempts' => 0, 'available_at' => $now, 'lease_token' => null, 'leased_until' => null, 'updated_at' => $now]);
        }
        $this->audit('probe_queued', 'Website:' . $id);
    }

    public function manualWebsite(): void
    {
        $this->writable();
        $ip = trim((string)$this->request->post('ip', ''));
        $port = (int)$this->request->post('port', 0);
        $scheme = (string)$this->request->post('scheme', '');
        $host = strtolower(rtrim(trim((string)$this->request->post('host', '')), '.'));
        if (!filter_var($ip, FILTER_VALIDATE_IP) || $port < 1 || $port > 65535 || !in_array($scheme, ['http', 'https'], true) || strlen($host) > 253 || ($host !== '' && !preg_match('/^[a-z0-9.-]+$/', $host))) $this->error('网站地址无效');
        $ip = inet_ntop(inet_pton($ip));
        $db = $this->db();
        $asset = $db->table('ip_assets')->where('ip', $ip)->find();
        if (!$asset) $this->error('公网 IP 尚未登记');
        $fingerprint = hash('sha256', implode('|', [$ip, $port, $scheme, $host]));
        $site = $db->table('websites')->where('fingerprint', $fingerprint)->find();
        if (!$site) {
            $now = date('Y-m-d H:i:s');
            $id = $db->table('websites')->insertGetId([
                'ip_asset_id' => $asset['id'], 'fingerprint' => $fingerprint, 'port' => $port,
                'scheme' => $scheme, 'host' => $host, 'source' => 'manual', 'status' => 'observed',
                'first_seen_at' => $now, 'last_seen_at' => $now, 'created_at' => $now, 'updated_at' => $now,
            ]);
        } else $id = $site['id'];
        $this->queueProbe((int)$id);
        $this->success('网站已加入验证队列', ['id' => $id]);
    }

    public function screenshot(): void
    {
        $id = (int)$this->request->get('id', 0);
        $site = $this->db()->table('websites')->where('id', $id)->field('screenshot_path')->find();
        $name = $site['screenshot_path'] ?? '';
        if (!preg_match('#^screenshots/[a-f0-9]{64}\.png$#', $name)) $this->error('该网站尚无截图', [], 404);
        $file = '/monitor-storage/app/private/' . $name;
        if (!is_file($file) || filesize($file) > 5 * 1024 * 1024) $this->error('截图不存在或超过 5 MiB', [], 404);
        $this->success('', ['image' => 'data:image/png;base64,' . base64_encode(file_get_contents($file))]);
    }

    public function export(): void
    {
        $resource = (string)$this->request->get('resource', '');
        $columns = match ($resource) {
            'ips' => ['ip' => '公网 IP', 'label' => '标签', 'first_seen_at' => '首次发现', 'last_seen_at' => '最后发现'],
            'websites' => ['ip' => '公网 IP', 'host' => '域名线索', 'port' => '端口', 'scheme' => '协议', 'status' => '验证状态', 'title' => '标题', 'description' => '网站描述', 'category' => '自动分类', 'manual_category' => '人工分类', 'last_probed_at' => '最近验证'],
            'alerts' => ['ip' => '公网 IP', 'node_name' => '观察节点', 'kind' => '类型', 'severity' => '级别', 'status' => '状态', 'title' => '标题', 'last_seen_at' => '时间'],
            default => null,
        };
        if (!$columns) $this->error('不支持的导出类型', [], 404);
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $resource . '.csv"');
        header('Cache-Control: private, no-store');
        $out = fopen('php://output', 'w');
        fwrite($out, "\xEF\xBB\xBF");
        fputcsv($out, array_values($columns), escape: '');
        $lastId = 0;
        $written = 0;
        while ($written < 50000) {
            $query = $this->db()->table($this->table($resource))->alias('m')->where('m.id', '>', $lastId);
            $fields = array_map(fn ($name) => 'm.' . $name, array_filter(array_keys($columns), fn ($name) => !in_array($name, ['ip', 'node_name'], true)));
            $fields[] = 'm.id AS export_id';
            if ($resource !== 'ips') {
                $query->leftJoin('ip_assets i', 'i.id=m.ip_asset_id');
                $fields[] = 'i.ip AS ip';
            }
            if ($resource === 'alerts') {
                $query->leftJoin('nodes n', 'n.id=m.node_id');
                $fields[] = 'n.name AS node_name';
            }
            $this->applyFilters($query, $resource);
            $rows = $query->field($fields)->order('m.id')->limit(min(500, 50000 - $written))->select()->toArray();
            if (!$rows) break;
            foreach ($rows as $row) {
                $lastId = (int)$row['export_id'];
                $cells = [];
                foreach (array_keys($columns) as $name) {
                    $value = (string)($row[$name] ?? '');
                    $cells[] = preg_match('/^[=+@\-\t\r\n]/', $value) ? "'" . $value : $value;
                }
                fputcsv($out, $cells, escape: '');
                $written++;
            }
            fflush($out);
        }
        fclose($out);
        exit;
    }
}
