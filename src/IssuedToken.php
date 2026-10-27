<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

/** A new token and the JWT to give the client. The JWT cannot be rebuilt later, so show it once. */
final readonly class IssuedToken
{
    public function __construct(public Token $token, public string $jwt) {}
}
