<?php

namespace App\Console\Commands;

use App\Models\AuditLog;
use App\Models\IpAsset;
use App\Models\Node;
use App\Models\Website;
use App\Services\ProbeQueue;
use App\Support\Ip;
use Illuminate\Console\Command;

class DiscoverSites extends Command
{
    protected $signature = 'monitor:discover {node : Configured node UUID} {target : One IP or small IPv4 CIDR} {--ports=80,443,8080,8443 : Up to 128 ports or ranges} {--scheme=both : http, https or both}';

    protected $description = 'Queue bounded active web discovery inside a node scope; IPv6 requires concrete addresses';

    public function handle(ProbeQueue $queue): int
    {
        $node = Node::findOrFail($this->argument('node'));
        $target = $this->argument('target');
        $ips = [];
        try {
            if (str_contains($target, '/')) {
                if (! Ip::validCidr($target) || str_contains($target, ':')) {
                    throw new \InvalidArgumentException('IPv6 请提供具体地址，不遍历网段');
                }
                [$ip,$bits] = explode('/', $target);
                if ((int) $bits < 24) {
                    throw new \InvalidArgumentException('一次最多枚举 /24；更大网段请分批');
                }
                $count = 2 ** (32 - (int) $bits);
                $base = (int) sprintf('%u', ip2long($ip));
                $base = intdiv($base, $count) * $count;
                for ($i = 0; $i < $count; $i++) {
                    $ips[] = long2ip($base + $i);
                }
            } else {
                $ips[] = Ip::normalize($target);
            }
            $ports = [];
            foreach (explode(',', $this->option('ports')) as $segment) {
                if (! preg_match('/^(\d+)(?:-(\d+))?$/', $segment, $m)) {
                    throw new \InvalidArgumentException('端口格式无效');
                }$a = (int) $m[1];
                $b = (int) ($m[2] ?? $m[1]);
                if ($a < 1 || $b > 65535 || $a > $b || $b - $a > 127) {
                    throw new \InvalidArgumentException('端口范围无效或超过128个');
                }for ($p = $a; $p <= $b; $p++) {
                    $ports[$p] = true;
                }
            }
            if (count($ports) > 128 || count($ips) * count($ports) > 2048) {
                throw new \InvalidArgumentException('一次最多128个端口、2048个 IP/端口组合');
            }
            $schemes = match ($this->option('scheme')) {
                'both' => ['http', 'https'],'http' => ['http'],'https' => ['https'],default => throw new \InvalidArgumentException('scheme 无效')
            };
            foreach ($ips as $ip) {
                if (! Ip::inRanges($ip, $node->cidrs)) {
                    throw new \InvalidArgumentException('目标超出该节点 CIDR：'.$ip);
                }
            }
        } catch (\InvalidArgumentException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
        $n = 0;
        foreach ($ips as $ip) {
            $asset = IpAsset::firstOrCreate(['ip' => $ip], ['version' => str_contains($ip, ':') ? 6 : 4, 'first_seen_at' => now(), 'last_seen_at' => now(), 'notes' => '由主动探测任务导入；不代表已观察到流量']);
            foreach (array_keys($ports) as $port) {
                foreach ($schemes as $scheme) {
                    $key = hash('sha256', implode('|', [$ip, $port, $scheme, '']));
                    $site = Website::firstOrCreate(['fingerprint' => $key], ['ip_asset_id' => $asset->id, 'port' => $port, 'scheme' => $scheme, 'host' => '', 'source' => 'active_candidate', 'status' => 'candidate', 'first_seen_at' => now(), 'last_seen_at' => now()]);
                    $queue->enqueue($site);
                    $n++;
                }
            }
        }
        AuditLog::record('discovery_queued', $node, ['target' => $target, 'ports' => $this->option('ports'), 'tasks' => $n]);
        $this->info("已排队 {$n} 项协议探测；候选不等于已部署网站。");

        return self::SUCCESS;
    }
}
