<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\PrimaryKeyConstraint;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;

/** The shape of the token table. The shipped migration uses it; use it in your own migration for another name. */
final readonly class TokensTable
{
    public const string DEFAULT_NAME = 'api_tokens';

    /** @param non-empty-string $name */
    public static function create(string $name = self::DEFAULT_NAME): Table
    {
        return Table::editor()
            ->setUnquotedName($name)
            ->setColumns(
                self::column('id', Types::STRING, 32),
                self::column('user_id', Types::STRING, 255),
                self::column('name', Types::STRING, 255),
                self::column('abilities', Types::JSON),
                self::column('tenant', Types::STRING, 64, nullable: true),
                self::column('created_at', Types::DATETIME_IMMUTABLE),
                self::column('expires_at', Types::DATETIME_IMMUTABLE, nullable: true),
                self::column('last_used_at', Types::DATETIME_IMMUTABLE, nullable: true),
                self::column('revoked_at', Types::DATETIME_IMMUTABLE, nullable: true),
            )
            ->setPrimaryKeyConstraint(
                PrimaryKeyConstraint::editor()->setUnquotedColumnNames('id')->create(),
            )
            ->setIndexes(
                Index::editor()->setUnquotedName($name . '_user_id_idx')->setUnquotedColumnNames('user_id')->create(),
                Index::editor()->setUnquotedName($name . '_tenant_idx')->setUnquotedColumnNames('tenant')->create(),
            )
            ->create();
    }

    /** @param non-empty-string $name */
    private static function column(string $name, string $type, ?int $length = null, bool $nullable = false): Column
    {
        return Column::editor()
            ->setUnquotedName($name)
            ->setTypeName($type)
            ->setLength($length)
            ->setNotNull(! $nullable)
            ->create();
    }
}
