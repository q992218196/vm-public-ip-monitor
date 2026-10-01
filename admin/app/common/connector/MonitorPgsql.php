<?php

declare(strict_types=1);

namespace app\common\connector;

use InvalidArgumentException;
use PDO;
use think\db\BaseQuery;
use think\db\connector\Pgsql;

/** PostgreSQL 17 field metadata without ThinkORM's obsolete table_msg() helper. */
class MonitorPgsql extends Pgsql
{
    public function getLastInsID(BaseQuery $query, ?string $sequence = null)
    {
        // LASTVAL() fails on UUID/fixed keys and aborts the PostgreSQL transaction.
        if (! $query->getAutoInc()) {
            return '';
        }

        return parent::getLastInsID($query, $sequence);
    }

    public function getFields(string $tableName): array
    {
        [$tableName] = explode(' ', trim($tableName));
        $tableName = trim($tableName, '"');
        if (! preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $tableName)) {
            throw new InvalidArgumentException('Invalid monitoring table name');
        }

        $sql = "SELECT c.column_name, c.data_type, c.is_nullable, c.column_default, c.is_identity,
                       EXISTS (
                           SELECT 1 FROM information_schema.table_constraints tc
                           JOIN information_schema.key_column_usage kcu
                             ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
                           WHERE tc.table_schema = c.table_schema AND tc.table_name = c.table_name
                             AND tc.constraint_type = 'PRIMARY KEY' AND kcu.column_name = c.column_name
                       ) AS is_primary
                  FROM information_schema.columns c
                 WHERE c.table_schema = current_schema() AND c.table_name = '".$tableName."'
                 ORDER BY c.ordinal_position";
        $rows = $this->getPDOStatement($sql)->fetchAll(PDO::FETCH_ASSOC);
        $fields = [];
        foreach ($rows as $row) {
            $fields[$row['column_name']] = [
                'name' => $row['column_name'],
                'type' => $row['data_type'],
                'notnull' => $row['is_nullable'] === 'NO',
                'default' => $row['column_default'],
                'primary' => in_array($row['is_primary'], [true, 't', '1', 1], true),
                'autoinc' => $row['is_identity'] === 'YES' || str_starts_with((string) $row['column_default'], 'nextval('),
            ];
        }

        return $this->fieldCase($fields);
    }
}
