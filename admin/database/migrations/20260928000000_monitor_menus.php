<?php

use think\facade\Db;
use think\migration\Migrator;

class MonitorMenus extends Migrator
{
    public function up(): void
    {
        $this->table('admin')->changeColumn('email', 'string', ['limit' => 255, 'default' => '', 'null' => false])->save();
        echo "Monitor migration: account schema ready\n";
        Db::name('config')->where('name', 'site_name')->update(['value' => 'VM 公网流量监控']);
        echo "Monitor migration: site config ready\n";
        if (!Db::name('admin_rule')->where('name', 'monitor')->find()) {
            $root = Db::name('admin_rule')->insertGetId([
                'pid' => 0, 'type' => 'menu_dir', 'title' => 'VM 流量监控', 'name' => 'monitor',
                'path' => 'monitor', 'icon' => 'fa fa-shield', 'weigh' => 998,
            ]);
            $items = [
                'nodes' => '采集节点', 'ips' => '公网 IP', 'websites' => '网站资产',
                'alerts' => '告警中心', 'rules' => '检测规则', 'exclusions' => '维护与白名单',
                'metrics' => '流量窗口', 'protocols' => '协议观察', 'tasks' => '网站探测任务', 'audit' => '审计日志',
            ];
            $position = 0;
            foreach ($items as $key => $title) {
                Db::name('admin_rule')->insert([
                    'pid' => $root, 'type' => 'menu', 'title' => $title,
                    'name' => 'monitor/' . $key, 'path' => 'monitor/' . $key,
                    'icon' => 'fa fa-circle-o', 'menu_type' => 'tab',
                    'component' => '/src/views/backend/monitor/index.vue',
                    'weigh' => 100 - $position++,
                ]);
            }
        }
        echo "Monitor migration: menus ready\n";
        if (!Db::name('admin_group')->where('name', '监控只读')->find()) {
            $ruleIds = Db::name('admin_rule')->whereLike('name', 'monitor%')->column('id');
            $accountIds = Db::name('admin_rule')->whereIn('name', ['routine', 'routine/adminInfo', 'routine/adminInfo/index', 'routine/adminInfo/edit'])->column('id');
            $dashboard = Db::name('admin_rule')->where('name', 'dashboard')->value('id');
            $dashboardIndex = Db::name('admin_rule')->where('name', 'dashboard/index')->value('id');
            Db::name('admin_group')->insert([
                'pid' => 0, 'name' => '监控只读',
                'rules' => implode(',', array_unique(array_merge(array_filter([$dashboard, $dashboardIndex]), $ruleIds, $accountIds))),
            ]);
        }
        echo "Monitor migration: viewer group ready\n";
        Db::name('admin_rule')->where('pid', 0)->whereNotIn('name', ['dashboard', 'auth', 'routine', 'monitor'])->update(['status' => 0]);
    }

    public function down(): void
    {
        $ids = Db::name('admin_rule')->whereLike('name', 'monitor%')->column('id');
        if ($ids) Db::name('admin_rule')->whereIn('id', $ids)->delete();
        Db::name('admin_group')->where('name', '监控只读')->delete();
    }
}
