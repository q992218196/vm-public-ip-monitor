<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\IpAsset;
use App\Models\Website;

class ExportController extends Controller
{
    public function __invoke(string $type)
    {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer']), 403);
        $model = match ($type) {
            'ips' => IpAsset::class,'alerts' => Alert::class,'websites' => Website::class,default => abort(404)
        };

        return response()->streamDownload(function () use ($model, $type) {
            $f = fopen('php://output', 'w');
            fwrite($f, "\xEF\xBB\xBF");
            $headers = match ($type) {
                'ips' => ['IP', '标签', '观察节点', '首次发现', '最后发现'],
                'websites' => ['ID', '公网 IP', '域名线索', '端口', '协议', '来源', '验证状态', '标题', '描述', '自动分类', '人工分类', '最近验证'],
                default => ['ID', 'IP', '观察节点', '类型', '级别', '状态', '时间'],
            };
            fputcsv($f, $headers, escape: '');
            $q = $model::query();
            if ($type === 'ips') {
                $q->with('nodes');
            } elseif ($type === 'websites') {
                $q->select(['id', 'ip_asset_id', 'host', 'port', 'scheme', 'source', 'status', 'title', 'description', 'category', 'manual_category', 'last_probed_at'])->with('ipAsset:id,ip');
            } else {
                $q->select(['id', 'ip_asset_id', 'node_id', 'kind', 'severity', 'status', 'last_seen_at'])->with(['node:id,name', 'ipAsset:id,ip']);
            }
            foreach ($q->orderBy('id')->limit(50000)->lazy(500) as $r) {
                $row = match ($type) {
                    'ips' => [$r->ip, $r->label, $r->nodes->pluck('name')->join(';'), $r->first_seen_at, $r->last_seen_at],
                    'websites' => [$r->id, $r->ipAsset?->ip, $r->host, $r->port, $r->scheme, $r->source, $r->status, $r->title, $r->description, $r->category, $r->manual_category, $r->last_probed_at],
                    default => [$r->id, $r->ipAsset?->ip, $r->node?->name, $r->kind, $r->severity, $r->status, $r->last_seen_at],
                };
                $row = array_map(function ($v) {
                    $s = (string) $v;

                    return preg_match('/^[=+@\-\t\r\n]/', $s) ? "'".$s : $s;
                }, $row);
                fputcsv($f, $row, escape: '');
            }
            fclose($f);
        }, $type.'.csv', ['Content-Type' => 'text/csv; charset=UTF-8']);
    }
}
