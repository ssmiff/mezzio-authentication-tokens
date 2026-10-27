<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use DateTimeImmutable;
use DateTimeZone;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Types;
use Override;
use UnexpectedValueException;

use function array_map;
use function array_values;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function strval;

use const JSON_THROW_ON_ERROR;

final readonly class DbalTokenRepository implements TokenRepository
{
    private string $table;

    public function __construct(private Connection $connection, string $table = TokensTable::DEFAULT_NAME)
    {
        $this->table = $connection->quoteSingleIdentifier($table);
    }

    #[Override]
    public function add(Token $token): void
    {
        $this->connection->insert(
            $this->table,
            [
                'id' => $token->id,
                'user_id' => $token->userId,
                'name' => $token->name,
                'abilities' => json_encode($token->abilities, JSON_THROW_ON_ERROR),
                'tenant' => $token->tenant,
                'created_at' => $token->createdAt,
                'expires_at' => $token->expiresAt,
                'last_used_at' => $token->lastUsedAt,
                'revoked_at' => $token->revokedAt,
            ],
            [
                'created_at' => Types::DATETIME_IMMUTABLE,
                'expires_at' => Types::DATETIME_IMMUTABLE,
                'last_used_at' => Types::DATETIME_IMMUTABLE,
                'revoked_at' => Types::DATETIME_IMMUTABLE,
            ],
        );
    }

    #[Override]
    public function find(string $id): ?Token
    {
        $row = $this->connection->fetchAssociative('SELECT * FROM ' . $this->table . ' WHERE id = ?', [$id]);

        return $row === false ? null : $this->hydrate($row);
    }

    #[Override]
    public function touch(string $id, DateTimeImmutable $at): void
    {
        $this->connection->update(
            $this->table,
            ['last_used_at' => $at],
            ['id' => $id],
            ['last_used_at' => Types::DATETIME_IMMUTABLE],
        );
    }

    #[Override]
    public function revoke(string $id, DateTimeImmutable $at): bool
    {
        return $this->revokeWhere('id', $id, $at) > 0;
    }

    #[Override]
    public function revokeForUser(string $userId, DateTimeImmutable $at): int
    {
        return $this->revokeWhere('user_id', $userId, $at);
    }

    #[Override]
    public function revokeForTenant(string $tenant, DateTimeImmutable $at): int
    {
        return $this->revokeWhere('tenant', $tenant, $at);
    }

    #[Override]
    public function prune(DateTimeImmutable $before): int
    {
        return (int) $this->connection->executeStatement(
            'DELETE FROM ' . $this->table . ' WHERE expires_at < ? OR revoked_at < ?',
            [$before, $before],
            [Types::DATETIME_IMMUTABLE, Types::DATETIME_IMMUTABLE],
        );
    }

    /** @param 'id'|'user_id'|'tenant' $column */
    private function revokeWhere(string $column, string $value, DateTimeImmutable $at): int
    {
        return (int) $this->connection->executeStatement(
            'UPDATE ' . $this->table . ' SET revoked_at = ? WHERE ' . $column . ' = ? AND revoked_at IS NULL',
            [$at, $value],
            [Types::DATETIME_IMMUTABLE],
        );
    }

    /**
     * @param array<string, mixed> $row
     * @psalm-suppress MixedAssignment, MixedArgument database values are mixed until checked
     */
    private function hydrate(array $row): Token
    {
        $abilities = is_string($row['abilities'] ?? null)
            ? json_decode($row['abilities'], true, flags: JSON_THROW_ON_ERROR)
            : [];
        $tenant    = $row['tenant'] ?? null;

        $id     = (string) $row['id'];
        $userId = (string) $row['user_id'];

        if ($id === '' || $userId === '') {
            throw new UnexpectedValueException('A stored token has no id or user id.');
        }

        return new Token(
            id: $id,
            userId: $userId,
            name: (string) $row['name'],
            abilities: is_array($abilities) ? array_values(array_map(strval(...), $abilities)) : [],
            tenant: is_string($tenant) ? $tenant : null,
            createdAt: $this->date($row['created_at']) ?? new DateTimeImmutable('now', new DateTimeZone('UTC')),
            expiresAt: $this->date($row['expires_at'] ?? null),
            lastUsedAt: $this->date($row['last_used_at'] ?? null),
            revokedAt: $this->date($row['revoked_at'] ?? null),
        );
    }

    private function date(mixed $value): ?DateTimeImmutable
    {
        return is_string($value) ? new DateTimeImmutable($value, new DateTimeZone('UTC')) : null;
    }
}
