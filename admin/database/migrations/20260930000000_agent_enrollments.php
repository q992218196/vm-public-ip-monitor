<?php

use think\migration\Migrator;

class AgentEnrollments extends Migrator
{
    public function up(): void
    {
        $this->execute('CREATE TABLE IF NOT EXISTS `ba_agent_enrollments` (
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
        $this->execute('DROP TABLE IF EXISTS `ba_agent_enrollments`');
    }
}
