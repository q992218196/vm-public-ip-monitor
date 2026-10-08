<?php

namespace App\Http\Controllers;

use App\Models\ProbeTask;
use App\Services\Screenshots;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ProbeController extends Controller
{
    public function claim()
    {
        return DB::transaction(function () {
            $task = ProbeTask::where('attempts', '<', 3)->where('available_at', '<=', now())->where(fn ($q) => $q->where('status', 'pending')->orWhere(fn ($q) => $q->where('status', 'leased')->where('leased_until', '<', now())))
                ->where(fn ($q) => $q->where('request_source', 'manual')->orWhere('mode', 'origin_test')->orWhereHas('website', fn ($site) => $site->where('discovery_kind', 'web_candidate')))
                ->orderByRaw("CASE WHEN request_source = 'manual' OR mode = 'origin_test' THEN 0 ELSE 1 END")->orderBy('id')->lockForUpdate()->first();
            if (! $task) {
                return response()->json(['task' => null]);
            }
            $token = bin2hex(random_bytes(32));
            $task->update(['status' => 'leased', 'attempts' => $task->attempts + 1, 'lease_token' => hash('sha256', $token), 'leased_until' => now()->addMinutes(3)]);
            $site = $task->website;

            return response()->json(['task' => ['id' => $task->id, 'lease_token' => $token, 'ip' => $site->ipAsset->ip, 'host' => $site->host, 'port' => $site->port, 'scheme' => $site->scheme, 'source' => $site->source, 'discovery_kind' => $site->discovery_kind, 'request_source' => $task->request_source, 'mode' => $task->mode]]);
        });
    }

    public function complete(Request $r, ProbeTask $task, Screenshots $screenshots)
    {
        $v = $r->validate(['lease_token' => 'required|string|size:64', 'status' => 'required|in:verified,failed',
            'title' => 'nullable|string|max:255', 'description' => 'nullable|string|max:1024', 'http_status' => 'nullable|integer|min:100|max:599', 'final_url' => 'nullable|string|max:2048',
            'category' => 'nullable|string|max:64', 'classification' => 'nullable|array', 'classification.confidence' => 'nullable|numeric|min:0|max:1',
            'classification.reasons' => 'nullable|array|max:20', 'classification.reasons.*' => 'string|max:255',
            'classification.method' => 'nullable|string|max:64', 'classification.review_required' => 'nullable|boolean', 'content_hash' => 'nullable|string|size:64',
            'classification.risk_level' => 'sometimes|in:medium,unknown',
            'classification.business_type' => 'sometimes|string|max:64', 'classification.nature' => 'sometimes|string|max:64',
            'classification.summary' => 'sometimes|string|max:1800',
            'classification.observed_at' => 'sometimes|date',
            'classification.limitations' => 'sometimes|array|max:5', 'classification.limitations.*' => 'string|max:255',
            'classification.findings' => 'sometimes|array|max:5',
            'classification.findings.*.category' => 'required|string|max:64', 'classification.findings.*.explanation' => 'required|string|max:255',
            'classification.findings.*.evidence' => 'required|array|max:4',
            'classification.findings.*.evidence.*.source' => 'required|in:title,description,body',
            'classification.findings.*.evidence.*.keyword' => 'required|string|max:64',
            'classification.findings.*.evidence.*.excerpt' => 'required|string|max:255',
            'classification.evidence' => 'sometimes|array|max:12',
            'classification.evidence.*.source' => 'required|in:title,description,body',
            'classification.evidence.*.keyword' => 'required|string|max:64',
            'classification.evidence.*.excerpt' => 'required|string|max:255',
            'ownership_status' => 'sometimes|in:manual,ip_only,dns_match,dns_mismatch,dns_unknown,origin_response',
            'ownership_evidence' => 'sometimes|array', 'ownership_evidence.host' => 'required_with:ownership_evidence|string|max:253',
            'ownership_evidence.checked_at' => 'required_with:ownership_evidence|date', 'ownership_evidence.method' => 'required_with:ownership_evidence|in:administrator_registered,literal_ip_comparison,dns_A_AAAA',
            'ownership_evidence.addresses' => 'present_with:ownership_evidence|array|max:16', 'ownership_evidence.addresses.*' => 'ip',
            'ownership_evidence.addresses_truncated' => 'sometimes|boolean', 'ownership_evidence.limitations' => 'sometimes|string|max:255',
            'ownership_evidence.origin_test' => 'sometimes|array:target_ip,checked_at,method,dns_status,limitations',
            'ownership_evidence.origin_test.target_ip' => 'required_with:ownership_evidence.origin_test|ip',
            'ownership_evidence.origin_test.checked_at' => 'required_with:ownership_evidence.origin_test|date',
            'ownership_evidence.origin_test.method' => 'required_with:ownership_evidence.origin_test|in:fixed_ip_host_sni',
            'ownership_evidence.origin_test.dns_status' => 'required_with:ownership_evidence.origin_test|in:dns_match,dns_mismatch,dns_unknown,manual,ip_only',
            'ownership_evidence.origin_test.limitations' => 'sometimes|string|max:255',
            'screenshot' => 'nullable|string|max:2800000', 'error' => 'nullable|string|max:1000']);

        return DB::transaction(function () use ($v, $task, $screenshots) {
            $task = ProbeTask::whereKey($task->id)->lockForUpdate()->firstOrFail();
            abort_unless($task->status === 'leased' && $task->leased_until->isFuture() && hash_equals($task->lease_token, hash('sha256', $v['lease_token'])), 409, '任务租约已失效');
            $site = $task->website;
            if (isset($v['ownership_status'])) {
                abort_unless(isset($v['ownership_evidence']), 422, '缺少归属证据');
                $expectedHost = strtolower(rtrim($site->host ?: $site->ipAsset->ip, '.'));
                abort_unless(strtolower(rtrim($v['ownership_evidence']['host'], '.')) === $expectedHost, 422, '域名归属证据不匹配');
                if (isset($v['ownership_evidence']['origin_test'])) {
                    abort_unless($task->mode === 'origin_test' && inet_pton($v['ownership_evidence']['origin_test']['target_ip']) === inet_pton($site->ipAsset->ip), 422, '源站测试任务或目标不匹配');
                }
                if ($v['ownership_status'] === 'origin_response') {
                    abort_unless($task->mode === 'origin_test' && isset($v['ownership_evidence']['origin_test']) && $v['status'] === 'verified', 422, '指定 IP 响应必须来自人工测试任务');
                }
                if ($v['ownership_status'] === 'dns_match') {
                    abort_unless(collect($v['ownership_evidence']['addresses'])->contains(fn ($ip) => inet_pton($ip) === inet_pton($site->ipAsset->ip)), 422, 'DNS 证据未包含目标 IP');
                }
                if ($v['ownership_status'] === 'manual') {
                    abort_unless($site->source === 'manual', 422, '被动线索不能标为人工登记');
                }
                if ($v['ownership_status'] === 'ip_only') {
                    $literal = trim($site->host ?: $site->ipAsset->ip, '[]');
                    abort_unless(filter_var($literal, FILTER_VALIDATE_IP) && inet_pton($literal) === inet_pton($site->ipAsset->ip), 422, 'IP 线索不匹配');
                }
                abort_if($v['status'] === 'verified' && in_array($v['ownership_status'], ['dns_mismatch', 'dns_unknown']), 422, '未归属线索不能验证为网站资产');
            }
            $path = null;
            if ($v['status'] === 'verified') {
                $path = $screenshots->store($v['screenshot'] ?? null);
            }
            $data = array_intersect_key($v, array_flip(['ownership_status', 'ownership_evidence'])) + ['status' => $v['status'], 'last_error' => $v['error'] ?? null, 'last_probed_at' => now()];
            if ($site->source === 'manual' && isset($v['ownership_evidence'])) {
                foreach (['registration', 'previous_dns'] as $field) {
                    if (isset($site->ownership_evidence[$field])) {
                        $data['ownership_evidence'][$field] = $site->ownership_evidence[$field];
                    }
                }
            }
            if (isset($v['ownership_evidence']) && ! isset($v['ownership_evidence']['origin_test']) && isset($site->ownership_evidence['origin_test'])) {
                $data['ownership_evidence']['origin_test'] = $site->ownership_evidence['origin_test'];
            }
            if ($v['status'] === 'verified') {
                $data += ['title' => $v['title'] ?? null, 'description' => $v['description'] ?? null, 'http_status' => $v['http_status'] ?? null, 'final_url' => $v['final_url'] ?? null, 'category' => $v['category'] ?? 'unknown', 'classification' => $v['classification'] ?? null, 'content_hash' => $v['content_hash'] ?? null, 'screenshot_path' => $path];
            }
            $site->update($data);
            if ($v['status'] === 'verified' && isset($v['http_status'])) {
                $site->update(['discovery_kind' => 'web_candidate']);
            }
            $task->update(['mode' => 'normal', 'status' => $v['status'] === 'verified' ? 'complete' : 'failed', 'last_error' => $v['error'] ?? null, 'lease_token' => null, 'leased_until' => null]);

            return response()->json(['accepted' => true, 'screenshot_stored' => $path !== null]);
        });
    }
}
