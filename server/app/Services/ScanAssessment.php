<?php

namespace App\Services;

class ScanAssessment
{
    public function assess(array $sample, string $severity = 'high'): array
    {
        $attempts = (int) ($sample['tcp_attempts'] ?? 0);
        $replies = isset($sample['synack_replies']) ? (int) $sample['synack_replies'] : null;
        $valid = $attempts > 0 && $replies !== null && $replies <= $attempts;
        $ratio = $valid ? round($replies / $attempts, 4) : null;
        $ports = $sample['ports'] ?? [];
        $web = count($ports) > 0 && ! array_diff($ports, [80, 443, 8080, 8443]);
        $review = $valid && $replies / $attempts >= 0.7 && (int) ($sample['max_ports_per_target'] ?? 0) === 1;
        $note = '仅当前观察节点；跨窗口取最大值，目标/端口数是保守下界。';
        if ($replies === null) {
            $note .= '当前 Agent 未上报 SYN-ACK 响应数，无法判断连接是否得到回复。';
        } elseif (! $valid) {
            $note .= '握手计数无法与本窗口发起次数配对，不能计算回复比例。';
        } else {
            $note .= "记录到 $replies/$attempts 次 TCP 发起获得 SYN-ACK。";
        }
        $note .= $review ? '多数连接得到握手回复，按中风险多目标连接待复核；单目标重复连接由独立规则评估。' : '较少握手回复或多端口行为需优先复核；高级别不表示已确认攻击。';
        $note .= '握手回复不代表应用请求成功，总出入字节可能混合其他连接，TCP 发起次数不是 HTTP 请求次数。';

        return [
            'severity' => $review && $severity === 'high' ? 'medium' : $severity,
            'title' => $review ? ($web ? '多目标 Web 端口连接（待复核）' : '疑似多目标双向连接（待复核）') : '疑似对外横向扫描',
            'confidence' => $review ? 'bidirectional_candidate' : 'behavioral',
            'note' => $note,
            'connection_analysis' => [
                'tcp_attempts' => $attempts, 'synack_replies' => $replies, 'reply_ratio' => $ratio,
                'web_ports_only' => $web, 'max_attempts_per_target' => $sample['max_attempts_per_target'] ?? null,
                'conclusion' => $review ? '连接多数得到回复，可能是正常业务，也不能排除应用层攻击' : '连接响应不足或多端口行为，需要进一步核对',
                'next_steps' => ['检查目标、可见域名及 HTTP 路径样本', '核对对应网站访问日志、状态码、频率及业务授权', 'HTTPS 请求正文需在服务端日志或授权解密位置核实'],
            ],
        ];
    }
}
