<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use DateTimeImmutable;

interface TokenRepository
{
    public function add(Token $token): void;

    public function find(string $id): ?Token;

    public function touch(string $id, DateTimeImmutable $at): void;

    /** @return bool whether a live token was revoked */
    public function revoke(string $id, DateTimeImmutable $at): bool;

    /** @return int the number of tokens revoked */
    public function revokeForUser(string $userId, DateTimeImmutable $at): int;

    /** @return int the number of tokens revoked */
    public function revokeForTenant(string $tenant, DateTimeImmutable $at): int;

    /**
     * Deletes tokens that expired or were revoked before `$before`.
     *
     * @return int the number of tokens deleted
     */
    public function prune(DateTimeImmutable $before): int;
}
