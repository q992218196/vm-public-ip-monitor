<?php

use think\migration\Migrator;

class AgentEnrollments extends Migrator
{
    public function up(): void
    {
        $name = $this->tableName();
        $this->execute('CREATE TABLE IF NOT EXISTS `' . $name . '` (
            `ticket_hash` CHAR(64) NOT NULL PRIMARY KEY,
            `node_id` CHAR(36) NOT NULL,
            `payload` MEDIUMTEXT NOT NULL,
            `expires_at` DATETIME NOT NULL,
            `created_at` DATETIME NOT NULL,
            KEY `agent_enrollments_expires_at` (`expires_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

    public function down(): void
    {
        $this->execute('DROP TABLE IF EXISTS `' . $this->tableName() . '`');
    }

    private function tableName(): string
    {
        $prefix = (string)config('database.connections.mysql.prefix', 'ba_');
        if (!preg_match('/^[a-zA-Z0-9_]*$/', $prefix)) throw new \RuntimeException('数据库前缀无效');
        return $prefix . 'agent_enrollments';
    }
}
