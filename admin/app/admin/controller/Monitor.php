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
        if (! $this->auth->isSuperAdmin() && ! $this->auth->check('monitor', mode: 'name')) {
            $this->error('没有监控数据访问权限', [], 403);
        }
    }

    private const TABLES = [
        'nodes' => ['name', 'id', 'enabled', 'cidrs', 'last_seen_at', 'health', 'health_observed_at', 'agent_desired_version', 'agent_update_requested_at'],
        'ips' => ['ip', 'id', 'version', 'label', 'first_seen_at', 'last_seen_at'],
        'websites' => ['id', 'ip_asset_id', 'host', 'port', 'scheme', 'status', 'ownership_status', 'title', 'description', 'category', 'manual_category', 'last_probed_at', 'last_seen_at'],
        'alerts' => ['id', 'node_id', 'ip_asset_id', 'title', 'kind', 'severity', 'status', 'occurrences', 'last_seen_at'],
        'rules' => ['id', 'name', 'kind', 'threshold', 'window_seconds', 'cooldown_seconds', 'severity', 'node_id', 'node_ids', 'enabled'],
        'exclusions' => ['id', 'cidr', 'kind', 'reason', 'node_id', 'expires_at'],
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
        if (! isset(self::TABLES[$resource])) {
            $this->error('未知的管理资源', [], 404);
        }

        return self::DATABASE_TABLES[$resource] ?? $resource;
    }

    protected function db()
    {
        return Db::connect('monitor');
    }

    protected function writable(): void
    {
        if (! $this->auth->isSuperAdmin()) {
            $this->error('仅管理员可以修改监控配置', [], 403);
        }
    }

    protected function audit(string $action, string $subject, array $details = []): void
    {
        $this->db()->table('audit_logs')->insert([
            'user_id' => null,
            'action' => $action,
            'subject' => $subject,
            'details' => json_encode(['buildadmin_id' => $this->auth->id] + $details, JSON_UNESCAPED_UNICODE),
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);
    }

    public function overview(): void
    {
        $db = $this->db();
        $this->success('', [
            'nodes' => $db->table('nodes')->where('enabled', true)->where('last_seen_at', '>', gmdate('Y-m-d H:i:s', time() - 300))->count(),
            'ips' => $db->table('ip_assets')->count(),
            'websites' => $db->table('websites')->whereIn('ownership_status', ['dns_match', 'manual', 'ip_only'])->count(),
            'alerts' => $db->table('monitor_events')->where('status', 'open')->count(),
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
        $resource = (string) $this->request->get('resource', '');
        $table = $this->table($resource);
        $page = max(1, (int) $this->request->get('page', 1));
        $limit = max(10, min(500, (int) $this->request->get('limit', 25)));
        $query = $this->db()->table($table)->alias('m');
        if ($resource === 'alerts') {
            $query->where('m.kind', '<>', 'new_website');
        }
        $fields = array_map(fn ($field) => 'm.'.$field, self::TABLES[$resource]);
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
        $direction = 'desc';
        if ($resource === 'alerts') {
            $sort = match ((string) $this->request->get('sort', 'last_seen_at')) {
                'title' => 'm.title', 'ip' => 'i.ip', 'severity' => 'm.severity',
                'status' => 'm.status', 'occurrences' => 'm.occurrences', default => 'm.last_seen_at',
            };
            $direction = $this->request->get('direction', 'desc') === 'asc' ? 'asc' : 'desc';
        }
        if ($resource === 'nodes') {
            $direction = $this->request->get('direction', 'desc') === 'asc' ? 'asc' : 'desc';
            $requestedSort = (string) $this->request->get('sort', 'last_seen_at');
            if ($requestedSort === 'agent_version') {
                $version = "m.health->>'version'";
                $query->orderRaw('CASE WHEN '.$version." ~ '^[0-9]{1,9}[.][0-9]{1,9}[.][0-9]{1,9}$' THEN string_to_array(".$version.", '.')::bigint[] END ".$direction.' NULLS LAST, '.$version.' '.$direction.' NULLS LAST');
                $sort = 'm.name';
            } else {
                $sort = $requestedSort === 'name' ? 'm.name' : 'm.last_seen_at';
            }
        }
        $rows = $query->field($fields)->order($sort, $direction)->order('m.id', 'desc')->page($page, $limit)->select()->toArray();
        foreach ($rows as &$row) {
            if ($resource === 'rules') {
                $row['node_ids'] = $this->decode($row['node_ids'] ?? null);
            }
            if ($resource === 'nodes') {
                $row['cidrs'] = $this->decode($row['cidrs'] ?? null);
                $row['health'] = $this->decode($row['health'] ?? null);
                $row['rss_mib'] = isset($row['health']['rss_bytes']) ? round($row['health']['rss_bytes'] / 1048576) : null;
                $row['kernel_drops'] = $row['health']['kernel_drops'] ?? null;
                $row['agent_version'] = $row['health']['version'] ?? null;
                $row['agent_update_error'] = $row['health']['update_error'] ?? null;
                if (! empty($row['agent_update_requested_at']) && (empty($row['health_observed_at']) || strtotime($row['health_observed_at']) < strtotime($row['agent_update_requested_at']))) {
                    $row['agent_update_error'] = null;
                }
            }
        }
        unset($row);
        $this->success('', ['list' => $rows, 'super' => $this->auth->isSuperAdmin()]);
    }

    public function count(): void
    {
        $resource = (string) $this->request->get('resource', '');
        $query = $this->db()->table($this->table($resource))->alias('m');
        if ($resource === 'alerts') {
            $query->where('m.kind', '<>', 'new_website');
        }
        if (in_array($resource, ['alerts', 'websites', 'metrics', 'protocols'], true)) {
            $query->leftJoin('ip_assets i', 'i.id=m.ip_asset_id');
        }
        if ($resource === 'tasks') {
            $query->leftJoin('websites w', 'w.id=m.website_id')->leftJoin('ip_assets i', 'i.id=w.ip_asset_id');
        }
        $this->applyFilters($query, $resource);
        $this->success('', ['total' => (int) $query->count()]);
    }

    private function applyFilters($query, string $resource): void
    {
        $node = (string) $this->request->get('node', '');
        $ip = (string) $this->request->get('ip', '');
        $status = (string) $this->request->get('status', '');
        $severity = (string) $this->request->get('severity', '');
        $search = trim((string) $this->request->get('search', ''));
        $review = (string) $this->request->get('review', '');
        if ($node !== '' && $resource === 'rules') {
            $query->where(function ($scope) use ($node) {
                $scope->where('m.node_id', $node)->whereOr(function ($quality) use ($node) {
                    $quality->where('m.kind', 'capture_degraded')->whereNull('m.node_id')
                        ->whereRaw('(m.node_ids IS NULL OR m.node_ids::jsonb @> ?::jsonb)', [json_encode([$node])]);
                });
            });
        } elseif ($node !== '' && in_array($resource, ['alerts', 'metrics', 'protocols', 'exclusions'], true)) {
            $query->where('m.node_id', $node);
        }
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            if ($resource === 'ips') {
                $query->where('m.ip', $ip);
            }
            if (in_array($resource, ['alerts', 'websites', 'metrics', 'tasks', 'protocols'], true)) {
                $query->where('i.ip', $ip);
            }
        }
        if ($status !== '' && in_array($resource, ['alerts', 'websites', 'tasks'], true)) {
            $query->where('m.status', $status);
        }
        if ($severity !== '' && $resource === 'alerts') {
            $query->where('m.severity', $severity);
        }
        if ($resource === 'websites') {
            $ownership = (string) $this->request->get('ownership', 'assets');
            $states = match ($ownership) {
                'assets' => ['dns_match', 'manual', 'ip_only'],
                'candidates' => ['unverified', 'dns_unknown', 'origin_response'],
                'foreign' => ['dns_mismatch'],
                'all' => null,
                default => ['dns_match', 'manual', 'ip_only'],
            };
            if ($states !== null) {
                $query->whereIn('m.ownership_status', $states);
            }
        }
        if ($resource === 'websites' && $review === '1') {
            $query->whereIn('m.category', ['疑似博彩', '疑似成人内容', '疑似诈骗引流', '支付平台线索', '贷款平台线索', '影视授权待核实'])->whereNull('m.manual_category');
        }
        if ($search !== '') {
            $field = match ($resource) {
                'nodes', 'rules' => 'm.name', 'ips' => 'm.ip', 'websites' => 'm.host',
                'alerts' => 'm.title', 'exclusions' => 'm.cidr', 'tasks' => 'w.host', default => null,
            };
            if ($field) {
                $query->where($field, 'like', '%'.addcslashes($search, '%_\\').'%');
            }
        }
    }

    protected function decode($value)
    {
        return is_string($value) ? (json_decode($value, true) ?: []) : $value;
    }

    public function detail(): void
    {
        $resource = (string) $this->request->get('resource', '');
        $id = (string) $this->request->get('id', '');
        $row = $this->db()->table($this->table($resource))->where('id', $id)->find();
        if (! $row) {
            $this->error('记录不存在', [], 404);
        }
        unset($row['token_hash']);
        if (isset($row['ip_asset_id'])) {
            $row['ip'] = $this->db()->table('ip_assets')->where('id', $row['ip_asset_id'])->value('ip');
        }
        foreach ($row as &$value) {
            if (is_string($value) && (str_starts_with($value, '{') || str_starts_with($value, '['))) {
                $decoded = json_decode($value, true);
                if (is_array($decoded)) {
                    $value = $decoded;
                }
            }
        }
        $this->success('', ['record' => $row]);
    }

    public function bulkAlerts(): void
    {
        $this->writable();
        $ids = $this->request->post('ids/a', []);
        $status = (string) $this->request->post('status', '');
        $resolution = trim((string) $this->request->post('resolution', ''));
        if (count($ids) < 1 || count($ids) > 500 || count(array_unique($ids)) !== count($ids) || ! in_array($status, ['open', 'acknowledged', 'resolved'], true) || $resolution === '' || mb_strlen($resolution) > 4000) {
            $this->error('告警选择、状态或处理记录无效');
        }
        foreach ($ids as $id) {
            if (! filter_var($id, FILTER_VALIDATE_INT)) {
                $this->error('告警 ID 无效');
            }
        }
        $db = $this->db();
        $db->startTrans();
        try {
            if (count($db->table('alerts')->whereIn('id', $ids)->lock(true)->column('id')) !== count($ids)) {
                $this->error('有告警已不存在');
            }
            $db->table('alerts')->whereIn('id', $ids)->update(['status' => $status, 'resolution' => $resolution, 'updated_at' => gmdate('Y-m-d H:i:s')]);
            $this->audit('alerts_bulk_handled', 'Alert:batch', ['ids' => $ids, 'status' => $status, 'resolution' => $resolution]);
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollback();
            throw $e;
        }
        $this->success(count($ids).' 条告警已更新');
    }

    protected function behaviorWhitelistScope(array $evidence, string $severity, ?array $requestedTargets = null): string
    {
        $sample = $evidence['sample'] ?? $evidence;
        $targets = $sample['targets'] ?? ($sample['egress_target_samples'] ?? []);
        $ports = $sample['ports'] ?? [];
        foreach ($sample['outbound_endpoints'] ?? [] as $endpoint) {
            $targets[] = $endpoint['peer_ip'];
            $ports[] = $endpoint['peer_port'];
        }
        foreach ($sample['target_endpoints'] ?? [] as $endpoint) {
            if (preg_match('/^(?:\[([^]]+)\]|([^:]+)):(\d+)$/', $endpoint, $match)) {
                $targets[] = $match[1] ?: $match[2];
                $ports[] = (int) $match[3];
            }
        }
        if (isset($sample['peer_ip'])) {
            $targets[] = $sample['peer_ip'];
            $ports[] = $sample['peer_port'];
        }
        $cidrs = $requestedTargets ?? $this->request->post('target_cidrs/a', []);
        if (count($cidrs) > 256) {
            $this->error('最多允许 256 个目标 IP/CIDR');
        }
        if (! $cidrs) {
            $cidrs = array_map(fn ($ip) => $ip.(str_contains($ip, ':') ? '/128' : '/32'), array_values(array_unique($targets)));
        }
        foreach ($cidrs as &$cidr) {
            if (! is_string($cidr)) {
                $this->error('目标 IP/CIDR 格式无效');
            }
            if (filter_var($cidr, FILTER_VALIDATE_IP)) {
                $cidr .= str_contains($cidr, ':') ? '/128' : '/32';
            }
            if (! $this->validCidr($cidr)) {
                $this->error('目标 IP/CIDR 格式无效');
            }
        }
        unset($cidr);

        return json_encode(['version' => 1, 'target_cidrs' => array_slice(array_values(array_unique($cidrs)), 0, 256), 'ports' => array_slice(array_values(array_unique(array_map('intval', $ports))), 0, 64),
            'max_value' => max(1, (float) ($evidence['value'] ?? 0) * 2), 'severity' => $severity, 'reviewed_at' => gmdate('c'),
            'policy' => 'Complete destination evidence only; unknown targets, ports, intensity or stronger evidence require review']);
    }

    public function whitelistAlert(): void
    {
        $this->writable();
        $id = (int) $this->request->post('id', 0);
        if ($id < 1) {
            $this->error('告警 ID 无效');
        }
        $db = $this->db();
        $db->startTrans();
        try {
            $alert = $db->table('alerts')->where('id', $id)->lock(true)->find();
            if (! $alert) {
                $this->error('告警不存在', [], 404);
            }
            if ($alert['kind'] === 'capture_degraded') {
                $this->error('采集覆盖下降属于采集质量问题，不支持加入白名单；请处理丢包或采集限额。');
            }
            $asset = null;
            $cidr = null;
            if ($alert['ip_asset_id']) {
                $asset = $db->table('ip_assets')->where('id', $alert['ip_asset_id'])->lock(true)->find();
                if (! $asset || ! filter_var($asset['ip'], FILTER_VALIDATE_IP)) {
                    $this->error('公网 IP 不存在', [], 404);
                }
                $cidr = $asset['ip'].(str_contains($asset['ip'], ':') ? '/128' : '/32');
            } elseif (! in_array($alert['kind'], ['node_offline', 'capture_degraded'], true)) {
                $this->error('此告警的公网 IP 资产已删除，无法确定白名单范围', [], 404);
            }
            $now = gmdate('Y-m-d H:i:s');
            $expires = gmdate('Y-m-d H:i:s', time() + 30 * 86400);
            $scope = ['node_id' => $alert['node_id'], 'cidr' => $cidr, 'kind' => $alert['kind']];
            $existing = $db->table('exclusions')->where($scope)->find();
            $behaviorScope = $asset ? $this->behaviorWhitelistScope((array) $this->decode($alert['evidence'] ?? null), $alert['severity']) : null;
            if ($existing) {
                $db->table('exclusions')->where('id', $existing['id'])->update(['expires_at' => $expires, 'behavior_scope' => $behaviorScope, 'updated_at' => $now]);
            } else {
                $db->table('exclusions')->insert($scope + [
                    'reason' => '管理员从告警 #'.$id.' 加入白名单，待业务复核',
                    'expires_at' => $expires, 'behavior_scope' => $behaviorScope, 'created_at' => $now, 'updated_at' => $now,
                ]);
            }
            $db->table('alerts')->where('node_id', $alert['node_id'])->where('ip_asset_id', $alert['ip_asset_id'])
                ->where('kind', $alert['kind'])->where('status', 'open')
                ->update(['status' => 'resolved', 'resolution' => '已建立 30 天定向业务例外；目标、端口、强度或证据变化时重新复核',
                    'updated_at' => $now]);
            $this->audit('alert_whitelisted', 'Alert:'.$id, ['node_id' => $alert['node_id'], 'ip' => $asset['ip'] ?? null, 'kind' => $alert['kind'], 'expires_at' => $expires]);
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollback();
            throw $e;
        }
        $this->success($asset ? '已保存 30 天定向业务例外；目标、端口、强度或证据变化时继续告警，截断样本不自动放行' : '已暂停此节点上报中断告警 30 天');
    }

    public function save(): void
    {
        $this->writable();
        $resource = (string) $this->request->post('resource', '');
        $table = $this->table($resource);
        if (! in_array($resource, ['ips', 'websites', 'rules', 'exclusions', 'nodes'], true)) {
            $this->error('该资源不可编辑');
        }
        $id = (string) $this->request->post('id', '');
        $data = $this->request->post('data/a', []);
        $allowed = match ($resource) {
            'ips' => ['label', 'notes'], 'websites' => ['manual_category'],
            'rules' => ['name', 'kind', 'enabled', 'severity', 'threshold', 'window_seconds', 'cooldown_seconds', 'node_id', 'node_ids'],
            'exclusions' => ['cidr', 'kind', 'reason', 'expires_at', 'node_id', 'target_cidrs', 'allowed_ports', 'max_value', 'allowed_severity'],
            'nodes' => ['name', 'enabled', 'cidrs', 'settings', 'notes'],
        };
        $data = array_intersect_key($data, array_flip($allowed));
        if (! $data) {
            $this->error('没有可保存的字段');
        }
        if ($resource === 'exclusions') {
            $targets = $data['target_cidrs'] ?? [];
            $ports = $data['allowed_ports'] ?? [];
            $maxValue = $data['max_value'] ?? 0;
            $severity = $data['allowed_severity'] ?? 'medium';
            unset($data['target_cidrs'], $data['allowed_ports'], $data['max_value'], $data['allowed_severity']);
            $existing = $id !== '' ? $this->db()->table('exclusions')->where('id', $id)->find() : [];
            $source = $data['cidr'] ?? $existing['cidr'] ?? null;
            if ($source) {
                if (! is_array($targets) || ! $targets || ! is_array($ports) || ! $ports || count($ports) > 64 || ! is_numeric($maxValue) || $maxValue < 1 || $maxValue > 1e12 || ! in_array($severity, ['low', 'medium', 'high'], true)) {
                    $this->error('IP 业务例外必须填写目标 IP/CIDR、允许端口、行为强度上限和证据级别；也可以从告警创建');
                }
                foreach ($ports as $port) {
                    if (filter_var($port, FILTER_VALIDATE_INT) === false || $port < 1 || $port > 65535) {
                        $this->error('允许端口无效');
                    }
                }
                $scope = json_decode($this->behaviorWhitelistScope(['sample' => ['ports' => array_map('intval', $ports)]], $severity, $targets), true);
                $scope['max_value'] = (float) $maxValue;
                $data['behavior_scope'] = json_encode($scope, JSON_UNESCAPED_UNICODE);
            }
        }
        $this->validateRecord($resource, $data, $id === '', $id);
        if (isset($data['cidrs'])) {
            $data['cidrs'] = json_encode($data['cidrs']);
        }
        if (isset($data['settings'])) {
            $data['settings'] = json_encode($data['settings']);
        }
        if (isset($data['node_ids'])) {
            $data['node_ids'] = json_encode($data['node_ids']);
        }
        $data['updated_at'] = gmdate('Y-m-d H:i:s');
        if ($id === '') {
            if (! in_array($resource, ['nodes', 'rules', 'exclusions'], true)) {
                $this->error('该资源不可新增');
            }
            if ($resource === 'nodes') {
                $data['id'] = $id = $this->uuid();
            }
            $data['created_at'] = $data['updated_at'];
            if ($resource === 'nodes') {
                $this->db()->table($table)->insert($data);
            } else {
                $id = (string) $this->db()->table($table)->insertGetId($data);
            }
        } else {
            if (! $this->db()->table($table)->where('id', $id)->find()) {
                $this->error('记录不存在', [], 404);
            }
            $this->db()->table($table)->where('id', $id)->update($data);
        }
        $this->audit('monitor_saved', ucfirst($resource).':'.$id, ['fields' => array_keys($data)]);
        $this->success('已保存', ['id' => $id]);
    }

    private function validateRecord(string $resource, array &$data, bool $creating, string $id = ''): void
    {
        if ($resource === 'nodes') {
            if (isset($data['name']) && (trim($data['name']) === '' || mb_strlen($data['name']) > 100)) {
                $this->error('节点名称无效');
            }
            if ($creating && (empty($data['name']) || empty($data['cidrs']))) {
                $this->error('节点名称和 CIDR 必填');
            }
            if (isset($data['cidrs'])) {
                if (! is_array($data['cidrs']) || count($data['cidrs']) < 1 || count($data['cidrs']) > 256) {
                    $this->error('CIDR 列表无效');
                }
                foreach ($data['cidrs'] as $cidr) {
                    if (! $this->validCidr((string) $cidr)) {
                        $this->error('CIDR 格式无效');
                    }
                }
            }
            if (isset($data['settings'])) {
                if (! is_array($data['settings'])) {
                    $this->error('节点配置无效');
                }
                foreach (['memory_soft_mib' => [128, 32768], 'memory_hard_mib' => [256, 65536], 'disk_limit_mib' => [640, 1048576]] as $key => [$min, $max]) {
                    if (isset($data['settings'][$key]) && (! filter_var($data['settings'][$key], FILTER_VALIDATE_INT) || $data['settings'][$key] < $min || $data['settings'][$key] > $max)) {
                        $this->error('节点资源上限无效');
                    }
                }
                if (isset($data['settings']['interfaces'])) {
                    if (! is_array($data['settings']['interfaces']) || count($data['settings']['interfaces']) < 1 || count($data['settings']['interfaces']) > 64) {
                        $this->error('采集接口配置无效');
                    }
                    foreach ($data['settings']['interfaces'] as $interface) {
                        if (! is_string($interface) || ! preg_match('/^[a-zA-Z0-9_.:-]{1,64}$/', $interface)) {
                            $this->error('采集接口名称无效');
                        }
                    }
                }
                if (isset($data['settings']['data_dir']) && ! preg_match('#^/[a-zA-Z0-9/_-]+$#', (string) $data['settings']['data_dir'])) {
                    $this->error('Agent 数据目录无效');
                }
                if (isset($data['settings']['memory_soft_mib'], $data['settings']['memory_hard_mib']) && (int) $data['settings']['memory_soft_mib'] > (int) $data['settings']['memory_hard_mib']) {
                    $this->error('工作内存不能超过服务硬限额');
                }
            }
            if (isset($data['enabled'])) {
                $data['enabled'] = (bool) $data['enabled'];
            }
        }
        if ($resource === 'ips' && isset($data['label']) && mb_strlen((string) $data['label']) > 255) {
            $this->error('标签过长');
        }
        if ($resource === 'websites' && array_key_exists('manual_category', $data)) {
            if (mb_strlen((string) $data['manual_category']) > 64) {
                $this->error('人工分类过长');
            }
            $data['manual_category'] = trim((string) $data['manual_category']) ?: null;
        }
        if ($resource === 'rules') {
            if ($creating && (empty($data['name']) || empty($data['kind']) || empty($data['threshold']))) {
                $this->error('规则名称、类型和阈值必填');
            }
            if (isset($data['name']) && (trim((string) $data['name']) === '' || mb_strlen((string) $data['name']) > 255)) {
                $this->error('规则名称无效');
            }
            if (isset($data['kind']) && ! in_array($data['kind'], ['vertical_scan', 'ssh_connections', 'smb_connections', 'rdp_connections', 'ftp_connections', 'udp_flow_burst', 'udp_packet_rate', 'single_target_attempts', 'tcp_connection_burst', 'egress_mbps', 'vpn_protocol', 'proxy_suspect', 'capture_degraded'], true)) {
                $this->error('规则类型无效');
            }
            $scope = $creating ? $data : array_replace($this->db()->table('rules')->where('id', $id)->find() ?: [], $data);
            if (($scope['kind'] ?? '') === 'capture_degraded') {
                if (array_key_exists('node_ids', $data) && $data['node_ids'] !== null && ! is_array($data['node_ids'])) {
                    $this->error('适用节点必须是列表或全部节点');
                }
                $targets = $this->decode($scope['node_ids'] ?? null);
                if ($targets !== null) {
                    if (! is_array($targets) || ! array_is_list($targets) || count($targets) > 500) {
                        $this->error('适用节点列表无效');
                    }
                    foreach ($targets as $target) {
                        if (! is_string($target) || ! preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $target)) {
                            $this->error('适用节点 ID 无效');
                        }
                    }
                    $targets = array_values(array_unique(array_map('strtolower', $targets)));
                    if ($targets && (int) $this->db()->table('nodes')->whereIn('id', $targets)->count() !== count($targets)) {
                        $this->error('指定节点不存在');
                    }
                }
                $data['node_ids'] = $targets;
            } else {
                if (! empty($data['node_ids'])) {
                    $this->error('多选节点范围仅适用于采集覆盖下降规则');
                }
                $data['node_ids'] = null;
            }
            if (isset($data['severity']) && ! in_array($data['severity'], ['low', 'medium', 'high'], true)) {
                $this->error('告警级别无效');
            }
            foreach (['threshold', 'window_seconds', 'cooldown_seconds'] as $field) {
                if (isset($data[$field]) && (! filter_var($data[$field], FILTER_VALIDATE_INT) || (int) $data[$field] < 1 || (int) $data[$field] > 1000000000)) {
                    $this->error('规则数值无效');
                }
            }
            if (isset($data['enabled'])) {
                $data['enabled'] = (bool) $data['enabled'];
            }
        }
        if ($resource === 'exclusions') {
            if ($creating && (empty($data['reason']) || empty($data['expires_at']))) {
                $this->error('白名单信息不完整');
            }
            if (array_key_exists('cidr', $data) && $data['cidr'] === '') {
                $data['cidr'] = null;
            }
            $scope = $creating ? $data : array_replace($this->db()->table('exclusions')->where('id', $id)->find() ?: [], $data);
            if (($scope['kind'] ?? '') === 'capture_degraded') {
                $this->error('采集覆盖下降不支持加入白名单，请处理采集质量。');
            }
            $nodeAlert = ($scope['kind'] ?? '') === 'node_offline';
            if ($nodeAlert) {
                if (empty($scope['node_id']) || ! empty($scope['cidr'])) {
                    $this->error('节点健康白名单必须指定节点，公网 IP/CIDR 留空');
                }
            } elseif (empty($scope['cidr']) || ! is_string($scope['cidr']) || ! $this->validCidr($scope['cidr'])) {
                $this->error('IP 告警白名单必须填写有效 CIDR');
            }
            if (isset($data['reason']) && (trim((string) $data['reason']) === '' || mb_strlen((string) $data['reason']) > 255)) {
                $this->error('原因无效');
            }
            if (isset($data['kind']) && $data['kind'] !== '' && ! in_array($data['kind'], ['horizontal_scan', 'vertical_scan', 'suspected_bruteforce', 'ssh_connections', 'smb_connections', 'rdp_connections', 'ftp_connections', 'udp_flow_burst', 'udp_packet_rate', 'single_target_attempts', 'tcp_connection_burst', 'egress_mbps', 'vpn_protocol', 'proxy_suspect', 'node_offline', 'capture_degraded'], true)) {
                $this->error('白名单类型无效');
            }
            if (isset($data['kind']) && $data['kind'] === '') {
                $data['kind'] = null;
            }
            if (isset($data['expires_at']) && strtotime((string) $data['expires_at'].' UTC') <= time()) {
                $this->error('失效时间必须在未来');
            }
        }
        if (isset($data['node_id']) && $data['node_id'] === '') {
            $data['node_id'] = null;
        }
        if (isset($data['node_id']) && $data['node_id'] !== null && ! $this->db()->table('nodes')->where('id', $data['node_id'])->find()) {
            $this->error('指定节点不存在');
        }
    }

    private function validCidr(string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2 || ! filter_var($parts[0], FILTER_VALIDATE_IP) || ! ctype_digit($parts[1])) {
            return false;
        }
        $max = str_contains($parts[0], ':') ? 128 : 32;

        return (int) $parts[1] <= $max;
    }

    private function uuid(): string
    {
        $hex = bin2hex(random_bytes(16));

        return substr($hex, 0, 8).'-'.substr($hex, 8, 4).'-4'.substr($hex, 13, 3).'-8'.substr($hex, 17, 3).'-'.substr($hex, 20, 12);
    }

    public function nodeConfig(): void
    {
        $this->writable();
        $id = (string) $this->request->post('id', '');
        $this->success('新配置已生成，旧凭据已撤销', ['config' => $this->rotateNodeConfig($id)]);
    }

    private function rotateNodeConfig(string $id): array
    {
        if (! filter_var(getenv('MONITOR_PUBLIC_URL'), FILTER_VALIDATE_URL)) {
            $this->error('请先配置管理端公开地址');
        }
        $node = $this->db()->table('nodes')->where('id', $id)->find();
        if (! $node) {
            $this->error('节点不存在', [], 404);
        }
        $token = bin2hex(random_bytes(32));
        $config = $this->nodeConfigPayload($node, $token);
        Db::name('agent_enrollments')->where('node_id', $id)->delete();
        $this->db()->table('nodes')->where('id', $id)->update(['token_hash' => hash('sha256', $token), 'updated_at' => gmdate('Y-m-d H:i:s')]);
        $this->audit('token_rotated', 'Node:'.$id);

        return $config;
    }

    private function nodeConfigPayload(array $node, string $token): array
    {
        $id = $node['id'];
        $settings = $this->decode($node['settings'] ?? null) ?: [];

        return [
            'node_id' => $id, 'server_url' => rtrim((string) getenv('MONITOR_PUBLIC_URL'), '/'), 'token' => $token,
            'interfaces' => $settings['interfaces'] ?? ['monitor0'], 'cidrs' => $this->decode($node['cidrs']),
            'data_dir' => $settings['data_dir'] ?? '/home/vm-monitor', 'memory_soft_mib' => (int) ($settings['memory_soft_mib'] ?? 2048),
            'memory_hard_mib' => (int) ($settings['memory_hard_mib'] ?? 4096), 'disk_limit_mib' => (int) ($settings['disk_limit_mib'] ?? 2048),
            'spool_limit_mib' => 512, 'capture_buffer_mib' => 16, 'flush_seconds' => 30,
            'max_ips' => 4096, 'max_flows' => 50000, 'max_reassembly' => 2048, 'max_sites' => 4096, 'allow_http_localhost' => false,
        ];
    }

    public function nodeBootstrap(): void
    {
        $this->writable();
        $this->publishedAgent();
        $id = (string) $this->request->post('id', '');
        if (! filter_var(getenv('MONITOR_PUBLIC_URL'), FILTER_VALIDATE_URL)) {
            $this->error('请先配置管理端公开地址');
        }
        $node = $this->db()->table('nodes')->where('id', $id)->find();
        if (! $node) {
            $this->error('节点不存在', [], 404);
        }
        $ticket = bin2hex(random_bytes(32));
        $token = bin2hex(random_bytes(32));
        $key = hash('sha256', (string) getenv('BUILDADMIN_TOKEN_KEY'), true);
        $nonce = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt(json_encode($this->nodeConfigPayload($node, $token), JSON_UNESCAPED_UNICODE), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        if ($cipher === false) {
            $this->error('无法生成安全配置');
        }
        $now = gmdate('Y-m-d H:i:s');
        Db::name('agent_enrollments')->where('expires_at', '<', $now)->delete();
        Db::name('agent_enrollments')->where('node_id', $id)->delete();
        Db::name('agent_enrollments')->insert([
            'ticket_hash' => hash('sha256', $ticket), 'node_id' => $id,
            'payload' => base64_encode($nonce.$tag.$cipher),
            'expires_at' => gmdate('Y-m-d H:i:s', time() + 600), 'created_at' => $now,
        ]);
        try {
            $this->db()->table('nodes')->where('id', $id)->update(['token_hash' => hash('sha256', $token), 'updated_at' => $now]);
            $this->audit('token_rotated', 'Node:'.$id);
        } catch (\Throwable $e) {
            Db::name('agent_enrollments')->where('ticket_hash', hash('sha256', $ticket))->delete();
            throw $e;
        }
        $this->audit('agent_bootstrap_issued', 'Node:'.$id);
        $this->success('一次性配置链接已生成，有效期 10 分钟', ['ticket' => $ticket, 'expires_in' => 600]);
    }

    private function publishedAgent(): array
    {
        $version = trim((string) @file_get_contents('/agent-dist/VERSION'));
        $manifest = (string) @file_get_contents('/agent-dist/SHA256SUMS');
        if (! preg_match('/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/', $version)
            || ! preg_match('/^([a-f0-9]{64})  vm-agent-linux-amd64$/m', $manifest, $match)
            || ! is_file('/agent-dist/vm-agent-linux-amd64')
            || ! hash_equals($match[1], hash_file('sha256', '/agent-dist/vm-agent-linux-amd64'))) {
            $this->error('尚未发布有效的 Agent 版本，请先运行 agent-builder');
        }

        return ['version' => $version, 'sha256' => $match[1]];
    }

    public function agentRelease(): void
    {
        $this->success('', ['release' => $this->publishedAgent()]);
    }

    public function agentUpdate(): void
    {
        $this->writable();
        $ids = $this->request->post('ids/a', []);
        if (count($ids) < 1 || count($ids) > 500 || count(array_unique($ids)) !== count($ids)) {
            $this->error('请选择 1–500 个节点');
        }
        foreach ($ids as $id) {
            if (! is_string($id) || ! preg_match('/^[a-f0-9-]{36}$/i', $id)) {
                $this->error('节点 ID 无效');
            }
        }
        $release = $this->publishedAgent();
        $db = $this->db();
        $existing = $db->table('nodes')->whereIn('id', $ids)->column('id');
        if (count($existing) !== count($ids)) {
            $this->error('有节点不存在');
        }
        $now = gmdate('Y-m-d H:i:s');
        $db->table('nodes')->whereIn('id', $ids)->update([
            'agent_desired_version' => $release['version'], 'agent_desired_sha256' => $release['sha256'],
            'agent_update_requested_at' => $now, 'updated_at' => $now,
        ]);
        $this->audit('agent_update_requested', 'Node:batch', ['ids' => $ids, 'version' => $release['version'], 'sha256' => $release['sha256']]);
        $this->success('更新指令已下发；节点将在下一次轮询时领取', ['version' => $release['version'], 'count' => count($ids)]);
    }

    public function probe(): void
    {
        $this->writable();
        $id = (int) $this->request->post('id', 0);
        $this->queueProbe($id);
        $this->success('已加入验证队列');
    }

    public function testOrigin(): void
    {
        $this->writable();
        $id = (int) $this->request->post('id', 0);
        $db = $this->db();
        $db->transaction(function () use ($db, $id) {
            $site = $db->table('websites')->where('id', $id)->lock(true)->find();
            if (! $site || ! filter_var($site['host'], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || filter_var($site['host'], FILTER_VALIDATE_IP)) {
                $this->error('请选择有效域名的网站线索');
            }
            if (! $db->table('ip_assets')->where('id', $site['ip_asset_id'])->find()) {
                $this->error('公网 IP 尚未登记');
            }
            $this->queueProbe($id);
            $db->table('probe_tasks')->where('website_id', $id)->update(['mode' => 'origin_test', 'status' => 'pending', 'attempts' => 0, 'available_at' => gmdate('Y-m-d H:i:s'), 'lease_token' => null, 'leased_until' => null, 'updated_at' => gmdate('Y-m-d H:i:s')]);
            $this->audit('website.origin_test', 'Website:'.$id, ['host' => $site['host'], 'ip_asset_id' => $site['ip_asset_id']]);
        });
        $this->success('已加入源站测试队列；请求成功后仍需核实归属');
    }

    private function queueProbe(int $id): void
    {
        if (! $this->db()->table('websites')->where('id', $id)->find()) {
            $this->error('网站不存在', [], 404);
        }
        $now = gmdate('Y-m-d H:i:s');
        $task = $this->db()->table('probe_tasks')->where('website_id', $id)->find();
        if (! $task) {
            $this->db()->table('probe_tasks')->insert(['website_id' => $id, 'status' => 'pending', 'attempts' => 0, 'available_at' => $now, 'created_at' => $now, 'updated_at' => $now]);
        } elseif (! in_array($task['status'], ['pending', 'leased'], true)) {
            $this->db()->table('probe_tasks')->where('website_id', $id)->update(['mode' => 'normal', 'status' => 'pending', 'attempts' => 0, 'available_at' => $now, 'lease_token' => null, 'leased_until' => null, 'updated_at' => $now]);
        }
        $this->audit('probe_queued', 'Website:'.$id);
    }

    public function confirmOrigin(): void
    {
        $this->writable();
        $id = (int) $this->request->post('id', 0);
        $reason = trim((string) $this->request->post('reason', ''));
        if ($reason === '' || mb_strlen($reason) > 1000) {
            $this->error('请填写源站归属核实依据，最多 1000 字');
        }
        $db = $this->db();
        $db->transaction(function () use ($db, $id, $reason) {
            $site = $db->table('websites')->where('id', $id)->lock(true)->find();
            if (! $site || ! filter_var($site['host'], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || filter_var($site['host'], FILTER_VALIDATE_IP)) {
                $this->error('请选择有效域名的网站线索');
            }
            if (! $db->table('ip_assets')->where('id', $site['ip_asset_id'])->find()) {
                $this->error('公网 IP 尚未登记');
            }
            $old = $this->decode($site['ownership_evidence'] ?? null) ?: [];
            $now = gmdate('Y-m-d\TH:i:s\Z');
            $evidence = [
                'host' => $site['host'], 'checked_at' => $now, 'method' => 'administrator_registered',
                'registration' => ['type' => 'cdn_origin', 'reason' => $reason, 'confirmed_by' => $this->auth->id, 'confirmed_at' => $now],
                'previous_dns' => $old['previous_dns'] ?? ['status' => $site['ownership_status'], 'evidence' => array_diff_key($old, array_flip(['registration', 'previous_dns']))],
            ];
            if (isset($old['origin_test'])) {
                $evidence['origin_test'] = $old['origin_test'];
            }
            $db->table('websites')->where('id', $id)->update(['source' => 'manual', 'ownership_status' => 'manual', 'ownership_evidence' => json_encode($evidence, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), 'updated_at' => gmdate('Y-m-d H:i:s')]);
            $db->table('probe_tasks')->where('website_id', $id)->whereIn('status', ['pending', 'leased'])->update(['mode' => 'normal', 'status' => 'pending', 'attempts' => 0, 'available_at' => gmdate('Y-m-d H:i:s'), 'lease_token' => null, 'leased_until' => null, 'updated_at' => gmdate('Y-m-d H:i:s')]);
            $this->audit('website.origin_registered', 'Website:'.$id, ['reason' => $reason, 'host' => $site['host'], 'ip_asset_id' => $site['ip_asset_id']]);
        });
        $this->queueProbe($id);
        $this->success('已登记源站并加入验证队列；人工登记不等于已确认站点部署');
    }

    public function manualWebsite(): void
    {
        $this->writable();
        $ip = trim((string) $this->request->post('ip', ''));
        $port = (int) $this->request->post('port', 0);
        $scheme = (string) $this->request->post('scheme', '');
        $host = strtolower(rtrim(trim((string) $this->request->post('host', '')), '.'));
        if (! filter_var($ip, FILTER_VALIDATE_IP) || $port < 1 || $port > 65535 || ! in_array($scheme, ['http', 'https'], true) || strlen($host) > 253 || ($host !== '' && ! preg_match('/^[a-z0-9.-]+$/', $host))) {
            $this->error('网站地址无效');
        }
        $ip = inet_ntop(inet_pton($ip));
        $db = $this->db();
        $asset = $db->table('ip_assets')->where('ip', $ip)->find();
        if (! $asset) {
            $this->error('公网 IP 尚未登记');
        }
        $fingerprint = hash('sha256', implode('|', [$ip, $port, $scheme, $host]));
        $site = $db->table('websites')->where('fingerprint', $fingerprint)->find();
        if (! $site) {
            $now = gmdate('Y-m-d H:i:s');
            $id = $db->table('websites')->insertGetId([
                'ip_asset_id' => $asset['id'], 'fingerprint' => $fingerprint, 'port' => $port,
                'scheme' => $scheme, 'host' => $host, 'source' => 'manual', 'ownership_status' => 'manual', 'status' => 'observed',
                'first_seen_at' => $now, 'last_seen_at' => $now, 'created_at' => $now, 'updated_at' => $now,
            ]);
        } else {
            $id = $site['id'];
            $db->table('websites')->where('id', $id)->update(['source' => 'manual', 'ownership_status' => 'manual']);
        }
        $this->queueProbe((int) $id);
        $this->success('网站已加入验证队列', ['id' => $id]);
    }

    public function screenshot(): void
    {
        $id = (int) $this->request->get('id', 0);
        $site = $this->db()->table('websites')->where('id', $id)->field('screenshot_path')->find();
        $name = $site['screenshot_path'] ?? '';
        if (! preg_match('#^screenshots/[a-f0-9]{64}\.png$#', $name)) {
            $this->error('该网站尚无截图', [], 404);
        }
        $file = '/monitor-storage/app/private/'.$name;
        if (! is_file($file) || filesize($file) > 5 * 1024 * 1024) {
            $this->error('截图不存在或超过 5 MiB', [], 404);
        }
        $this->success('', ['image' => 'data:image/png;base64,'.base64_encode(file_get_contents($file))]);
    }

    public function export(): void
    {
        $resource = (string) $this->request->get('resource', '');
        $columns = match ($resource) {
            'ips' => ['ip' => '公网 IP', 'label' => '标签', 'first_seen_at' => '首次发现', 'last_seen_at' => '最后发现'],
            'websites' => ['ip' => '公网 IP', 'host' => '域名线索', 'port' => '端口', 'scheme' => '协议', 'status' => '验证状态', 'ownership_status' => '归属状态', 'title' => '标题', 'description' => '网站描述', 'category' => '自动分类', 'manual_category' => '人工分类', 'last_probed_at' => '最近验证'],
            'alerts' => ['ip' => '公网 IP', 'node_name' => '观察节点', 'kind' => '类型', 'severity' => '级别', 'status' => '状态', 'title' => '标题', 'last_seen_at' => '时间'],
            default => null,
        };
        if (! $columns) {
            $this->error('不支持的导出类型', [], 404);
        }
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="'.$resource.'.csv"');
        header('Cache-Control: private, no-store');
        $out = fopen('php://output', 'w');
        fwrite($out, "\xEF\xBB\xBF");
        fputcsv($out, array_values($columns), escape: '');
        $lastId = 0;
        $written = 0;
        while ($written < 50000) {
            $query = $this->db()->table($this->table($resource))->alias('m')->where('m.id', '>', $lastId);
            if ($resource === 'alerts') {
                $query->where('m.kind', '<>', 'new_website');
            }
            $fields = array_map(fn ($name) => 'm.'.$name, array_filter(array_keys($columns), fn ($name) => ! in_array($name, ['ip', 'node_name'], true)));
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
            if (! $rows) {
                break;
            }
            foreach ($rows as $row) {
                $lastId = (int) $row['export_id'];
                $cells = [];
                foreach (array_keys($columns) as $name) {
                    $value = (string) ($row[$name] ?? '');
                    $cells[] = preg_match('/^[=+@\-\t\r\n]/', $value) ? "'".$value : $value;
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
