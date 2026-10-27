<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use DateInterval;
use Mezzio\Authentication\AuthenticationInterface;
use Mezzio\Authentication\UserInterface;
use Override;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Ssmiff\MezzioAuthenticationTokens\Jwt\JwtCodec;

use function preg_match;

/** Authenticates `Authorization: Bearer <jwt>` against the api_tokens table. */
final readonly class TokenAuthentication implements AuthenticationInterface
{
    public function __construct(
        private JwtCodec $jwt,
        private TokenRepository $tokens,
        private ResponseFactoryInterface $responses,
        private ClockInterface $clock,
        private int $touchInterval = 60,
    ) {}

    #[Override]
    public function authenticate(ServerRequestInterface $request): ?UserInterface
    {
        if (preg_match('/^Bearer\s+(\S+)$/i', $request->getHeaderLine('Authorization'), $matches) !== 1) {
            return null;
        }

        $id = $this->jwt->decode($matches[1]);

        if ($id === null) {
            return null;
        }

        $token = $this->tokens->find($id);
        $now   = $this->clock->now();

        if ($token === null || ! $token->isUsable($now)) {
            return null;
        }

        $stale = $now->sub(new DateInterval('PT' . $this->touchInterval . 'S'));

        if ($token->lastUsedAt === null || $token->lastUsedAt <= $stale) {
            $this->tokens->touch($token->id, $now);
        }

        return new TokenUser($token);
    }

    #[Override]
    public function unauthorizedResponse(ServerRequestInterface $request): ResponseInterface
    {
        return $this->responses->createResponse(401)->withHeader('WWW-Authenticate', 'Bearer');
    }
}
