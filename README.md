# ssmiff/mezzio-authentication-tokens

Personal access tokens for Mezzio APIs, in the style of Laravel Sanctum. A [mezzio-authentication](https://docs.mezzio.dev/mezzio-authentication/) adapter checks `Authorization: Bearer <jwt>` against tokens stored in the database, so a token can be revoked, expires, and carries abilities and an optional tenant.

```
composer require ssmiff/mezzio-authentication-tokens
```

`laminas-component-installer` registers `Ssmiff\MezzioAuthenticationTokens\ConfigProvider`. The provider of [ssmiff/mezzio-container-helpers](https://github.com/ssmiff/mezzio-container-helpers) and [ssmiff/mezzio-doctrine](https://github.com/ssmiff/mezzio-doctrine) must be registered too, and a PSR-17 `ResponseFactoryInterface` must be in the container.

## How a request is authenticated

1. `TokenIssuer::issue()` inserts a row in `api_tokens` and returns a signed JWT (HS256).
2. The client sends the JWT as a bearer token.
3. `TokenAuthentication` checks the signature, issuer and `exp`, then loads the row named by the JWT's `jti`. A row that is missing, revoked or expired rejects the request, whatever the JWT says.
4. It returns a `TokenUser`: the identity is the token's user id, the roles are its abilities, and `tenant()` is its tenant.

The JWT also carries `sub`, `abilities` and `tenant` so an SPA can read them, but the server never trusts those claims; it reads the row. No secret is stored, so there is nothing in the database that can be replayed: a token is only usable with the signing key.

## Setup

```php
'authentication_tokens' => [
    'connection'     => 'landlord',   // doctrine.connections entry holding the table; null is the default connection
    'table'          => 'api_tokens', // the table holding the tokens; see "Another table name"
    'key'            => getenv('API_TOKENS_KEY'),   // required, at least 32 bytes; keep it out of version control
    'issuer'         => 'authentication-tokens', // iss claim; JWTs from another issuer are rejected
    'ttl'            => 2_592_000,    // default lifetime in seconds (30 days); null never expires
    'touch_interval' => 60,           // seconds between last_used_at updates for one token
],
```

Register the shipped migration on the same connection, then migrate:

```php
'doctrine' => ['migrations' => ['connections' => ['landlord' => ['migrations_paths' => [
    'Ssmiff\\MezzioAuthenticationTokens\\Migrations' => 'vendor/ssmiff/mezzio-authentication-tokens/migrations',
]]]]],
```

```
vendor/bin/laminas migrations:migrate --conn=landlord
```

The module does not choose the connection for you: a migration registered for a connection you do not use would create the table in the wrong database. Dates are stored in UTC.

### Another table name

The shipped migration creates `api_tokens`. For another name, set `authentication_tokens.table` and do not register the module's migration path; write a migration of your own instead, which reuses the table definition:

```php
final class Version20261101000000 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        TokensTable::create(...);
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable('personal_access_tokens');
    }
}
```

The name must be a plain identifier (letters, digits and underscores).

## Routes

`AuthServiceId::MIDDLEWARE` is a `Mezzio\Authentication\AuthenticationMiddleware` built with this module's adapter. It is registered under its own name and the module does not alias `Mezzio\Authentication\AuthenticationInterface`, so another adapter (OAuth2, say) can sit beside it on other routes.

```php
$app->get('/api/notes', [AuthServiceId::MIDDLEWARE, ListNotesHandler::class]);
```

A missing, invalid, revoked or expired token gets `401` with `WWW-Authenticate: Bearer`. Handlers read the user with `$request->getAttribute(Mezzio\Authentication\UserInterface::class)`, a `TokenUser` with `can('notes:write')` (`*` grants everything).

## Issuing and revoking

```php
$issued = $issuer->issue(userId: '42', name: 'spa', abilities: ['notes:read'], tenant: 'acme', ttl: 3600);
$issued->jwt;          // hand this to the client; it cannot be rebuilt later
$issuer->revoke($issued->token->id);
$issuer->revokeForUser('42');
$issuer->revokeForTenant('acme');
```

The module does not check passwords or have users of its own; call `issue()` from your login handler once you have authenticated someone.

```
vendor/bin/laminas api-tokens:issue 42 --name=spa --ability=notes:read --tenant=acme --ttl=3600
vendor/bin/laminas api-tokens:revoke <id>          # or --user=42 or --tenant=acme
vendor/bin/laminas api-tokens:prune --days=30      # delete tokens that ended more than 30 days ago
```

## Tenants

`tenant` is an opaque string; this module does not depend on a tenancy package. To make a tenant-bound token select the tenant, add a resolver that reads `TokenUser::tenant()` and list it before the others. With [ssmiff/mezzio-tenancy](https://github.com/ssmiff/mezzio-tenancy):

```php
final readonly class TokenTenantResolver implements TenantResolver
{
    public function identify(ServerRequestInterface $request): ?string
    {
        $user = $request->getAttribute(UserInterface::class);

        return $user instanceof TokenUser ? $user->tenant() : null;
    }
}
```

Config lists are appended when merged, not replaced, so a resolver added in your own config would run after the module's defaults, and a header could then override the token. Replace the list with `Laminas\Stdlib\ArrayUtils\MergeReplaceKey`:

```php
'tenancy' => ['resolvers' => new MergeReplaceKey([TokenTenantResolver::class, HeaderResolver::class])],
```

Put the token middleware before the tenancy middleware on the route.

## Adding another mechanism later

Give each mechanism its own middleware service and assign them per route, or write an adapter that tries several in turn. This module only provides the bearer-token adapter.
