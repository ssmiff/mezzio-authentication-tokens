<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Test;

use Doctrine\DBAL\Connection;
use Laminas\ServiceManager\ServiceManager;
use Override;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Authentication\UserInterface;
use Psr\Http\Message\ServerRequestInterface;
use Ssmiff\MezzioAuthenticationTokens\Jwt\JwtCodec;
use Ssmiff\MezzioAuthenticationTokens\AuthServiceId;
use Ssmiff\MezzioAuthenticationTokens\Test\Fixture\RecordingHandler;
use Ssmiff\MezzioAuthenticationTokens\Token;
use Ssmiff\MezzioAuthenticationTokens\TokenAuthentication;
use Ssmiff\MezzioAuthenticationTokens\TokenIssuer;
use Ssmiff\MezzioAuthenticationTokens\TokenRepository;
use Ssmiff\MezzioAuthenticationTokens\TokenUser;
use Ssmiff\MezzioContainerHelpers\Services;
use Psr\Http\Server\MiddlewareInterface;

use function base64_decode;
use function explode;
use function json_decode;
use function str_repeat;
use function substr;

final class TokenAuthenticationTest extends TestCase
{
    private TokenIssuer $issuer;
    private TokenAuthentication $auth;
    private TokenRepository $tokens;
    private Connection $connection;
    private ServiceManager $services;

    #[Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->services   = $this->container();
        $this->issuer     = Services::get($this->services, TokenIssuer::class);
        $this->auth       = Services::get($this->services, TokenAuthentication::class);
        $this->tokens     = Services::get($this->services, TokenRepository::class);
        $this->connection = Services::get($this->services, Connection::class, AuthServiceId::CONNECTION);
    }

    private static function bearer(string $jwt): ServerRequestInterface
    {
        return new ServerRequest(headers: ['Authorization' => 'Bearer ' . $jwt]);
    }

    public function testAValidTokenAuthenticatesAsItsUserWithItsAbilitiesAndTenant(): void
    {
        $issued = $this->issuer->issue('user-7', 'spa', ['notes:read', 'notes:write'], 'acme');

        $user = $this->auth->authenticate(self::bearer($issued->jwt));

        self::assertInstanceOf(TokenUser::class, $user);
        self::assertSame('user-7', $user->getIdentity());
        self::assertSame(['notes:read', 'notes:write'], $user->getRoles());
        self::assertSame('acme', $user->tenant());
        self::assertSame($issued->token->id, $user->getDetail('token_id'));
        self::assertTrue($user->can('notes:read'));
        self::assertFalse($user->can('notes:delete'));
    }

    public function testAWildcardTokenCanDoAnything(): void
    {
        $user = $this->auth->authenticate(self::bearer($this->issuer->issue('u', 'all')->jwt));

        self::assertInstanceOf(TokenUser::class, $user);
        self::assertTrue($user->can('anything'));
        self::assertNull($user->tenant());
    }

    public function testTheJwtCarriesTheTenantAndAbilitiesForTheClient(): void
    {
        $jwt = $this->issuer->issue('u', 'spa', ['a'], 'acme')->jwt;

        $claims = json_decode((string) base64_decode(explode('.', $jwt)[1], true), true);

        self::assertIsArray($claims);
        self::assertSame('acme', $claims['tenant']);
        self::assertSame(['a'], $claims['abilities']);
        self::assertSame('u', $claims['sub']);
    }

    public function testRequestsWithoutAUsableBearerTokenAreRejected(): void
    {
        self::assertNull($this->auth->authenticate(new ServerRequest()));
        self::assertNull($this->auth->authenticate(new ServerRequest(headers: ['Authorization' => 'Basic abc'])));
        self::assertNull($this->auth->authenticate(self::bearer('not-a-jwt')));
    }

    public function testATamperedJwtIsRejected(): void
    {
        $jwt = $this->issuer->issue('u', 'spa')->jwt;

        self::assertNull($this->auth->authenticate(self::bearer(substr($jwt, 0, -4) . 'AAAA')));
    }

    public function testAJwtSignedWithAnotherKeyIsRejected(): void
    {
        $other = Services::get($this->container(['key' => str_repeat('x', 32)]), TokenIssuer::class);

        self::assertNull($this->auth->authenticate(self::bearer($other->issue('u', 'spa')->jwt)));
    }

    public function testAJwtFromAnotherIssuerIsRejected(): void
    {
        $other = Services::get($this->container(['issuer' => 'someone-else']), TokenIssuer::class);

        self::assertNull($this->auth->authenticate(self::bearer($other->issue('u', 'spa')->jwt)));
    }

    public function testARevokedTokenIsRejectedEvenThoughItsSignatureIsValid(): void
    {
        $issued = $this->issuer->issue('u', 'spa');

        self::assertTrue($this->issuer->revoke($issued->token->id));
        self::assertNull($this->auth->authenticate(self::bearer($issued->jwt)));
        self::assertFalse($this->issuer->revoke($issued->token->id));
    }

    public function testAnExpiredTokenIsRejected(): void
    {
        $jwt = $this->issuer->issue('u', 'spa', ttl: 60)->jwt;

        $this->clock->advance('PT59S');
        self::assertInstanceOf(TokenUser::class, $this->auth->authenticate(self::bearer($jwt)));

        $this->clock->advance('PT2S');
        self::assertNull($this->auth->authenticate(self::bearer($jwt)));
    }

    public function testATokenWithoutATtlNeverExpires(): void
    {
        $container = $this->container(['ttl' => null]);
        $jwt       = Services::get($container, TokenIssuer::class)->issue('u', 'forever')->jwt;
        $auth      = Services::get($container, TokenAuthentication::class);

        $this->clock->advance('P3650D');

        self::assertInstanceOf(TokenUser::class, $auth->authenticate(self::bearer($jwt)));
    }

    public function testATokenWhoseRowWasDeletedIsRejected(): void
    {
        $issued = $this->issuer->issue('u', 'spa');
        $this->connection->executeStatement('DELETE FROM api_tokens');

        self::assertNull($this->auth->authenticate(self::bearer($issued->jwt)));
    }

    public function testLastUsedIsUpdatedAtMostOncePerInterval(): void
    {
        $issued = $this->issuer->issue('u', 'spa');
        $id     = $issued->token->id;

        self::assertNull($this->tokens->find($id)?->lastUsedAt);

        $this->auth->authenticate(self::bearer($issued->jwt));
        $first = $this->tokens->find($id)?->lastUsedAt;
        self::assertEquals($this->clock->now(), $first);

        $this->clock->advance('PT30S');
        $this->auth->authenticate(self::bearer($issued->jwt));
        self::assertEquals($first, $this->tokens->find($id)?->lastUsedAt);

        $this->clock->advance('PT31S');
        $this->auth->authenticate(self::bearer($issued->jwt));
        self::assertEquals($this->clock->now(), $this->tokens->find($id)?->lastUsedAt);
    }

    public function testTokensCanBeRevokedByUserOrTenant(): void
    {
        $this->issuer->issue('u1', 'a', tenant: 'acme');
        $this->issuer->issue('u1', 'b', tenant: 'globex');
        $this->issuer->issue('u2', 'c', tenant: 'acme');

        self::assertSame(2, $this->issuer->revokeForTenant('acme'));
        self::assertSame(1, $this->issuer->revokeForUser('u1'));
        self::assertSame(0, $this->issuer->revokeForUser('u2'));
    }

    public function testPruneDeletesOnlyTokensThatEndedBeforeTheCutoff(): void
    {
        $this->issuer->issue('u', 'short', ttl: 60);
        $this->issuer->issue('u', 'long', ttl: 86_400 * 100);
        $revoked = $this->issuer->issue('u', 'revoked', ttl: 86_400 * 100);
        $this->issuer->revoke($revoked->token->id);

        $this->clock->advance('P10D');

        self::assertSame(2, $this->tokens->prune($this->clock->now()));
        self::assertNotNull($this->connection->fetchOne('SELECT id FROM api_tokens'));
        self::assertSame(1, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM api_tokens'));
    }

    public function testTheUnauthorizedResponseIsA401WithABearerChallenge(): void
    {
        $response = $this->auth->unauthorizedResponse(new ServerRequest());

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testTheMiddlewarePassesTheUserToTheHandlerOrReturns401(): void
    {
        $middleware = Services::get($this->services, MiddlewareInterface::class, AuthServiceId::MIDDLEWARE);
        $handler    = new RecordingHandler();

        $denied = $middleware->process(new ServerRequest(), $handler);
        self::assertSame(401, $denied->getStatusCode());
        self::assertNull($handler->lastRequest());

        $accepting = new RecordingHandler();
        $jwt       = $this->issuer->issue('u', 'spa', tenant: 'acme')->jwt;
        $allowed   = $middleware->process(self::bearer($jwt), $accepting);
        self::assertSame(204, $allowed->getStatusCode());

        $user = $accepting->lastRequest()?->getAttribute(UserInterface::class);
        self::assertInstanceOf(TokenUser::class, $user);
        self::assertSame('acme', $user->tenant());
    }

    public function testAShortSigningKeyIsRefused(): void
    {
        $this->expectExceptionMessage('at least 32 bytes');

        Services::get($this->container(['key' => 'short']), JwtCodec::class);
    }

    public function testTheRepositoryRoundTripsATokenInUtc(): void
    {
        $issued = $this->issuer->issue('u', 'spa', ['a', 'b'], 'acme', 3600);
        $found  = $this->tokens->find($issued->token->id);

        self::assertInstanceOf(Token::class, $found);
        self::assertSame(['a', 'b'], $found->abilities);
        self::assertSame('acme', $found->tenant);
        self::assertEquals($this->clock->now(), $found->createdAt);
        self::assertEquals($this->clock->now()->modify('+1 hour'), $found->expiresAt);
        self::assertNull($this->tokens->find('missing'));
    }

    public function testTheTableNameComesFromConfig(): void
    {
        $container = $this->container(['table' => 'my_tokens']);
        $issued    = Services::get($container, TokenIssuer::class)->issue('u', 'spa');
        $connection = Services::get($container, Connection::class, AuthServiceId::CONNECTION);

        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM my_tokens'));
        self::assertInstanceOf(
            TokenUser::class,
            Services::get($container, TokenAuthentication::class)->authenticate(self::bearer($issued->jwt)),
        );
    }

    public function testATableNameThatIsNotAPlainIdentifierIsRefused(): void
    {
        $this->expectExceptionMessage('plain table name');

        Services::get($this->container(['table' => 'tokens; DROP TABLE x']), TokenIssuer::class);
    }
}
