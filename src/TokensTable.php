<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\PrimaryKeyConstraint;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;
use InvalidArgumentException;

use function preg_match;
use function sprintf;

/** The shape of the token table. The shipped migration uses it; use it in your own migration for another name. */
final readonly class TokensTable
{
    public const string DEFAULT_NAME = 'api_tokens';

    /**
     * Checks a table name before it is used in SQL anywhere in this module.
     *
     * Lowercase only, so the unquoted name in CREATE TABLE and the quoted name in queries are the same table on
     * every platform (PostgreSQL folds unquoted names to lowercase). At most 50 characters, so the index names
     * built from it stay within PostgreSQL's 63-character limit.
     *
     * @return non-empty-string
     * @throws InvalidArgumentException
     */
    public static function name(string $name): string
    {
        if ($name === '' || preg_match('/^[a-z_][a-z0-9_]{0,49}$/D', $name) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Invalid token table name "%s": use a plain table name of lowercase letters, digits and underscores, '
                . 'starting with a letter or underscore, at most 50 characters.',
                $name,
            ));
        }

        return $name;
    }

    public static function create(string $name = self::DEFAULT_NAME): Table
    {
        $name = self::name($name);

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
