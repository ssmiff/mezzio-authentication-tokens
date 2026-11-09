<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Test;

use Doctrine\DBAL\Connection;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use Laminas\ServiceManager\ServiceManager;
use Override;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Authentication\UserInterface;
use Psr\Http\Message\ServerRequestInterface;
use Ssmiff\MezzioAuthenticationTokens\Jwt\JwtCodec;
use Ssmiff\MezzioAuthenticationTokens\AuthServiceId;
use Ssmiff\MezzioAuthenticationTokens\DbalTokenRepository;
use Ssmiff\MezzioAuthenticationTokens\Test\Fixture\FrozenClock;
use Ssmiff\MezzioAuthenticationTokens\Test\Fixture\RecordingHandler;
use Ssmiff\MezzioAuthenticationTokens\Token;
use Ssmiff\MezzioAuthenticationTokens\TokenAuthentication;
use Ssmiff\MezzioAuthenticationTokens\TokenIssuer;
use Ssmiff\MezzioAuthenticationTokens\TokenRepository;
use Ssmiff\MezzioAuthenticationTokens\TokenUser;
use Ssmiff\MezzioAuthenticationTokens\TokensTable;
use Ssmiff\MezzioContainerHelpers\Services;
use Psr\Http\Server\MiddlewareInterface;

use function base64_decode;
use function explode;
use function json_decode;
use function str_repeat;
use function substr;
use function var_export;

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

    /** @return iterable<string, array{string}> */
    public static function invalidTableNames(): iterable
    {
        yield 'SQL'              => ['tokens; DROP TABLE x'];
        yield 'quote'            => ['to"kens'];
        yield 'trailing newline' => ["api_tokens\n"];
        yield 'schema-qualified' => ['public.api_tokens'];
        yield 'uppercase'        => ['MyTokens'];
        yield 'leading digit'    => ['1tokens'];
        yield 'empty'            => [''];
        yield 'over 50 chars'    => [str_repeat('a', 51)];
    }

    #[DataProvider('invalidTableNames')]
    public function testAnInvalidTableNameFromConfigIsRefused(string $table): void
    {
        // The container wraps the factory's InvalidArgumentException, so match the message.
        $this->expectExceptionMessage('Invalid token table name');

        Services::get($this->container(['table' => $table]), TokenIssuer::class);
    }

    #[DataProvider('invalidTableNames')]
    public function testTheRepositoryAndTheSchemaRefuseAnInvalidTableNameThemselves(string $table): void
    {
        $connection = Services::get($this->container(), Connection::class, AuthServiceId::CONNECTION);

        try {
            new DbalTokenRepository($connection, $table);
            self::fail('The repository accepted ' . var_export($table, true));
        } catch (InvalidArgumentException) {
        }

        $this->expectException(InvalidArgumentException::class);
        TokensTable::create($table);
    }

    public function testTheLongestAllowedTableNameWorks(): void
    {
        $table     = str_repeat('a', 50);
        $container = $this->container(['table' => $table]);
        $issued    = Services::get($container, TokenIssuer::class)->issue('u', 'spa');

        self::assertInstanceOf(
            TokenUser::class,
            Services::get($container, TokenAuthentication::class)->authenticate(self::bearer($issued->jwt)),
        );
    }

    public function testExpiryIsStoredInUtcWhateverTheClocksTimezone(): void
    {
        // A clock five hours ahead of UTC: before the fix, its local times were stored as if they were UTC, so
        // tokens lived five hours longer than their ttl.
        $this->clock = new FrozenClock('+05:00');
        $container   = $this->container();
        $issued      = Services::get($container, TokenIssuer::class)->issue('u', 'spa', ttl: 3600);
        $connection  = Services::get($container, Connection::class, AuthServiceId::CONNECTION);
        $auth        = Services::get($container, TokenAuthentication::class);

        self::assertSame(
            '2026-10-27 13:00:00',
            $connection->fetchOne('SELECT expires_at FROM api_tokens WHERE id = ?', [$issued->token->id]),
        );

        $this->clock->advance('PT59M');
        self::assertInstanceOf(TokenUser::class, $auth->authenticate(self::bearer($issued->jwt)));

        $this->clock->advance('PT2M');
        self::assertNull($auth->authenticate(self::bearer($issued->jwt)));
    }

    public function testRevocationIsStoredInUtcWhateverTheClocksTimezone(): void
    {
        $this->clock = new FrozenClock('-08:00');
        $container   = $this->container();
        $issuer      = Services::get($container, TokenIssuer::class);
        $issued      = $issuer->issue('u', 'spa');
        $connection  = Services::get($container, Connection::class, AuthServiceId::CONNECTION);

        $issuer->revoke($issued->token->id);

        self::assertSame(
            '2026-10-27 12:00:00',
            $connection->fetchOne('SELECT revoked_at FROM api_tokens WHERE id = ?', [$issued->token->id]),
        );
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalidNumbers(): iterable
    {
        yield 'zero ttl'                => [['ttl' => 0], 'authentication_tokens.ttl'];
        yield 'negative ttl'            => [['ttl' => -60], 'authentication_tokens.ttl'];
        yield 'negative touch interval' => [['touch_interval' => -1], 'authentication_tokens.touch_interval'];
    }

    /** @param array<string, mixed> $config */
    #[DataProvider('invalidNumbers')]
    public function testInvalidLifetimesInConfigAreRefused(array $config, string $key): void
    {
        $this->expectExceptionMessage($key);

        $container = $this->container($config);
        Services::get($container, TokenIssuer::class);
        Services::get($container, TokenAuthentication::class);
    }

    public function testATouchIntervalOfZeroUpdatesLastUsedOnEveryRequest(): void
    {
        $container = $this->container(['touch_interval' => 0]);
        $issued    = Services::get($container, TokenIssuer::class)->issue('u', 'spa');

        self::assertInstanceOf(
            TokenUser::class,
            Services::get($container, TokenAuthentication::class)->authenticate(self::bearer($issued->jwt)),
        );
    }

    public function testTheIssuerRefusesALifetimeBelowOneSecond(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->issuer->issue('u', 'spa', ttl: 0);
    }
}
