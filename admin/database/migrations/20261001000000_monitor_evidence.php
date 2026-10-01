<?php

use think\facade\Db;
use think\migration\Migrator;

class MonitorEvidence extends Migrator
{
    public function up(): void
    {
        Db::name('admin_rule')->where('name', 'monitor/alerts')->update(['component' => '/src/views/backend/monitor/events.vue']);
        $root = Db::name('admin_rule')->where('name', 'monitor')->value('id');
        if ($root && ! Db::name('admin_rule')->where('name', 'monitor/ai')->find()) {
            Db::name('admin_rule')->insert(['pid' => $root, 'type' => 'menu', 'title' => 'AI 分析设置', 'name' => 'monitor/ai', 'path' => 'monitor/ai', 'icon' => 'fa fa-magic', 'menu_type' => 'tab', 'component' => '/src/views/backend/monitor/ai.vue', 'weigh' => 50]);
        }
    }

    public function down(): void
    {
        Db::name('admin_rule')->where('name', 'monitor/alerts')->update(['component' => '/src/views/backend/monitor/index.vue']);
        Db::name('admin_rule')->where('name', 'monitor/ai')->delete();
    }
}
