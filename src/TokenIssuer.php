<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use DateInterval;
use Psr\Clock\ClockInterface;
use Ssmiff\MezzioAuthenticationTokens\Jwt\JwtCodec;

use function bin2hex;
use function random_bytes;

final readonly class TokenIssuer
{
    /** @param int|null $ttl default lifetime in seconds; null issues tokens that never expire */
    public function __construct(
        private TokenRepository $tokens,
        private JwtCodec $jwt,
        private ClockInterface $clock,
        private ?int $ttl = 2_592_000,
    ) {}

    /**
     * @param non-empty-string $userId
     * @param list<string> $abilities `*` grants everything
     * @param int|null $ttl lifetime in seconds for this token; null uses the configured default
     */
    public function issue(
        string $userId,
        string $name,
        array $abilities = ['*'],
        ?string $tenant = null,
        ?int $ttl = null,
    ): IssuedToken {
        $now      = $this->clock->now();
        $lifetime = $ttl ?? $this->ttl;
        $token    = new Token(
            id: bin2hex(random_bytes(16)),
            userId: $userId,
            name: $name,
            abilities: $abilities,
            tenant: $tenant,
            createdAt: $now,
            expiresAt: $lifetime === null ? null : $now->add(new DateInterval('PT' . $lifetime . 'S')),
        );

        $this->tokens->add($token);

        return new IssuedToken($token, $this->jwt->encode($token));
    }

    public function revoke(string $id): bool
    {
        return $this->tokens->revoke($id, $this->clock->now());
    }

    public function revokeForUser(string $userId): int
    {
        return $this->tokens->revokeForUser($userId, $this->clock->now());
    }

    public function revokeForTenant(string $tenant): int
    {
        return $this->tokens->revokeForTenant($tenant, $this->clock->now());
    }
}
