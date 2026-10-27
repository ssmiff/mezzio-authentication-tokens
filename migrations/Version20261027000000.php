<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Override;
use Ssmiff\MezzioAuthenticationTokens\TokensTable;

/** Creates the default table name; for another, write a migration of your own around TokensTable::create(). */
final class Version20261027000000 extends AbstractMigration
{
    #[Override]
    public function up(Schema $schema): void
    {
        foreach ($this->connection->getDatabasePlatform()->getCreateTableSQL(TokensTable::create()) as $sql) {
            $this->addSql($sql);
        }
    }

    #[Override]
    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE ' . $this->connection->quoteSingleIdentifier(TokensTable::DEFAULT_NAME));
    }
}
