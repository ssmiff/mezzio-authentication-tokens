<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Test;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\Migrations\AbstractMigration;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Ssmiff\MezzioAuthenticationTokens\Migrations\Version20261027000000;
use Ssmiff\MezzioAuthenticationTokens\TokensTable;

final class MigrationTest extends TestCase
{
    public function testTheShippedMigrationCreatesAndDropsTheDefaultTable(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $manager    = $connection->createSchemaManager();

        self::migrate($connection, 'up');
        self::assertTrue($manager->tablesExist([TokensTable::DEFAULT_NAME]));
        self::assertCount(9, $manager->introspectSchema()->getTable(TokensTable::DEFAULT_NAME)->getColumns());

        self::migrate($connection, 'down');
        self::assertFalse($manager->tablesExist([TokensTable::DEFAULT_NAME]));
    }

    /** @param 'up'|'down' $direction */
    private static function migrate(Connection $connection, string $direction): void
    {
        $migration = new Version20261027000000($connection, new NullLogger());
        $schema    = $connection->createSchemaManager()->introspectSchema();

        $direction === 'up' ? $migration->up($schema) : $migration->down($schema);

        self::execute($connection, $migration);
    }

    private static function execute(Connection $connection, AbstractMigration $migration): void
    {
        foreach ($migration->getSql() as $query) {
            $connection->executeStatement($query->getStatement());
        }
    }
}
