<?php

namespace App\Console\Commands;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

#[Signature('monitor:reassess-scans')]
#[Description('兼容入口：使用统一连接规则重新分级，不改变人工审核结果')]
class ReassessScans extends Command
{
    public function handle(): int
    {
        return $this->call('monitor:reassess-connections');
    }
}
