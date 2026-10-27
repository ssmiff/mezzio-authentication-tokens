<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

use Laminas\ServiceManager\Factory\FactoryInterface;
use Ssmiff\MezzioAuthenticationTokens\Jwt\JwtCodec;

/**
 * @psalm-type Dependencies = array{
 *     factories: array<string, class-string<FactoryInterface>>,
 * }
 */
final readonly class ConfigProvider
{
    private const array COMMANDS = [
        'api-tokens:issue' => Console\IssueCommand::class,
        'api-tokens:revoke' => Console\RevokeCommand::class,
        'api-tokens:prune' => Console\PruneCommand::class,
    ];

    /** @return array<string, mixed> */
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->dependencies(),
            'laminas-cli' => ['commands' => self::COMMANDS],
            'authentication_tokens' => [
                // The doctrine.connections entry holding api_tokens; null uses the default connection.
                // Add the module's migrations_paths for it; see the README.
                'connection' => null,
                // The table holding the tokens. A name other than api_tokens needs your own migration; see the README.
                'table' => TokensTable::DEFAULT_NAME,
                // HS256 signing key, at least 32 bytes. Required; keep it out of version control.
                'key' => null,
                // The iss claim; a JWT from another issuer is rejected.
                'issuer' => 'authentication-tokens',
                // Default lifetime in seconds (30 days); null issues tokens that never expire.
                'ttl' => 2_592_000,
                // Seconds between last_used_at updates for one token.
                'touch_interval' => 60,
            ],
        ];
    }

    /** @return array<string, class-string> */
    public function commands(): array
    {
        return self::COMMANDS;
    }

    /** @return Dependencies */
    public function dependencies(): array
    {
        $factories = [
            AuthServiceId::CONNECTION => Factory\ConnectionFactory::class,
            AuthServiceId::CLOCK => Factory\ClockFactory::class,
            AuthServiceId::MIDDLEWARE => Factory\ServicesFactory::class,
            TokenRepository::class => Factory\ServicesFactory::class,
            JwtCodec::class => Factory\ServicesFactory::class,
            TokenIssuer::class => Factory\ServicesFactory::class,
            TokenAuthentication::class => Factory\ServicesFactory::class,
        ];

        foreach (self::COMMANDS as $class) {
            $factories[$class] = Factory\ServicesFactory::class;
        }

        return ['factories' => $factories];
    }
}
