<?php

namespace App\Services;

use App\Models\Exclusion;
use App\Support\Ip;

class BehaviorWhitelist
{
    public function evaluate(Exclusion $entry, array $evidence): array
    {
        $scope = $entry->behavior_scope;
        if (! is_array($scope) || ($scope['version'] ?? 0) !== 1) {
            return ['match' => false, 'reason' => '历史白名单缺少目标与行为范围，请重新审核'];
        }
        $sample = $evidence['sample'] ?? $evidence;
        if (($evidence['connection_analysis']['category'] ?? '') === 'strong_anomaly') {
            return ['match' => false, 'reason' => '出现更强异常证据，业务例外不抑制此告警'];
        }
        if (! empty($sample['cardinality_capped'])) {
            return ['match' => false, 'reason' => '目标统计触及限额，无法确认仍在已批准业务范围'];
        }
        $quality = $sample['capture_quality'] ?? [];
        if (($quality['state_dropped'] ?? 0) > 0 || ($quality['kernel_drops'] ?? 0) > max(1, $quality['captured'] ?? 0) * 0.01 || ($quality['decode_skipped'] ?? 0) > max(1, $quality['captured'] ?? 0) * 0.1) {
            return ['match' => false, 'reason' => '采集质量不足，无法确认目标与连接行为仍在业务范围'];
        }
        $targets = $sample['targets'] ?? [];
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
            $ports[] = $sample['peer_port'] ?? null;
        }
        foreach ($sample['egress_target_samples'] ?? [] as $target) {
            $targets[] = $target;
        }
        $targets = array_values(array_unique($targets));
        $ports = array_values(array_unique(array_filter($ports)));
        if (! $targets || ! $ports) {
            return ['match' => false, 'reason' => '缺少完整目标或端口证据，继续复核'];
        }
        foreach ($targets as $target) {
            if (! collect($scope['target_cidrs'] ?? [])->contains(fn ($cidr) => Ip::contains($cidr, $target))) {
                return ['match' => false, 'reason' => '出现未批准的目标 IP：'.$target];
            }
        }
        if (array_diff($ports, $scope['ports'] ?? [])) {
            return ['match' => false, 'reason' => '出现未批准的目标端口'];
        }
        if (($sample['unique_targets'] ?? count($targets)) > count($targets) || ($sample['egress_target_count'] ?? count($targets)) > count($targets)
            || ($sample['port_samples_truncated'] ?? false) || ($sample['endpoint_samples_truncated'] ?? false) || ($sample['outbound_samples_truncated'] ?? false)) {
            return ['match' => false, 'reason' => '当前目标或端口仅有截断样本，不能据此抑制全部检测'];
        }
        $value = (float) ($evidence['value'] ?? 0);
        if ($value > max(1, (float) ($scope['max_value'] ?? 0))) {
            return ['match' => false, 'reason' => '连接或流量强度超出已审核业务上限'];
        }
        $ranks = ['low' => 1, 'medium' => 2, 'high' => 3];
        if (($ranks[$evidence['assessed_severity'] ?? 'medium'] ?? 3) > ($ranks[$scope['severity'] ?? 'low'] ?? 1)) {
            return ['match' => false, 'reason' => '行为证据级别超过批准范围'];
        }

        return ['match' => true, 'reason' => '目标、端口与行为强度均在已审核范围'];
    }
}
