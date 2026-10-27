<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use DateTimeImmutable;

/** A row of the api_tokens table. The JWT handed to the client only carries `$id`; this is what is trusted. */
final readonly class Token
{
    /**
     * @param non-empty-string $id
     * @param non-empty-string $userId
     * @param list<string> $abilities
     */
    public function __construct(
        public string $id,
        public string $userId,
        public string $name,
        public array $abilities,
        public ?string $tenant,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $expiresAt = null,
        public ?DateTimeImmutable $lastUsedAt = null,
        public ?DateTimeImmutable $revokedAt = null,
    ) {}

    public function isUsable(DateTimeImmutable $now): bool
    {
        return $this->revokedAt === null && ($this->expiresAt === null || $this->expiresAt > $now);
    }
}
