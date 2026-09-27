<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\IpAsset;

class ExportController extends Controller
{
    public function __invoke(string $type)
    {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer']), 403);
        $model = match ($type) {
            'ips' => IpAsset::class,'alerts' => Alert::class,default => abort(404)
        };

        return response()->streamDownload(function () use ($model, $type) {
            $f = fopen('php://output', 'w');
            fwrite($f, "\xEF\xBB\xBF");
            fputcsv($f, $type === 'ips' ? ['IP', '标签', '观察节点', '首次发现', '最后发现'] : ['ID', 'IP', '观察节点', '类型', '级别', '状态', '时间'], escape: '');
            $q = $model::query();
            if ($type === 'ips') {
                $q->with('nodes');
            } else {
                $q->with(['node', 'ipAsset']);
            }
            foreach ($q->orderBy('id')->limit(50000)->lazy(500) as $r) {
                $row = $type === 'ips' ? [$r->ip, $r->label, $r->nodes->pluck('name')->join(';'), $r->first_seen_at, $r->last_seen_at] : [$r->id, $r->ipAsset?->ip, $r->node?->name, $r->kind, $r->severity, $r->status, $r->last_seen_at];
                $row = array_map(function ($v) {
                    $s = (string) $v;

                    return preg_match('/^[=+@\-\t\r\n]/', $s) ? "'".$s : $s;
                }, $row);
                fputcsv($f, $row, escape: '');
            }fclose($f);
        }, $type.'.csv', ['Content-Type' => 'text/csv; charset=UTF-8']);
    }
}
