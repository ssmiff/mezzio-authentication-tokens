<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use Mezzio\Authentication\UserInterface;
use Override;

use function in_array;

/** The authenticated user: the identity is the token's user id and the roles are its abilities. */
final readonly class TokenUser implements UserInterface
{
    public function __construct(public Token $token) {}

    #[Override]
    public function getIdentity(): string
    {
        return $this->token->userId;
    }

    /** @return list<string> */
    #[Override]
    public function getRoles(): iterable
    {
        return $this->token->abilities;
    }

    /** @return array{token_id: string, token_name: string, tenant: string|null} */
    #[Override]
    public function getDetails(): array
    {
        return ['token_id' => $this->token->id, 'token_name' => $this->token->name, 'tenant' => $this->token->tenant];
    }

    #[Override]
    public function getDetail(string $name, mixed $default = null): mixed
    {
        return $this->getDetails()[$name] ?? $default;
    }

    /** The tenant the token was issued for, if any. */
    public function tenant(): ?string
    {
        return $this->token->tenant;
    }

    /** Whether the token has the ability; `*` grants every ability. */
    public function can(string $ability): bool
    {
        return in_array('*', $this->token->abilities, true) || in_array($ability, $this->token->abilities, true);
    }
}
