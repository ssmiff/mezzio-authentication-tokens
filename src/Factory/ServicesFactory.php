<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Factory;

use Doctrine\DBAL\Connection;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Mezzio\Authentication\AuthenticationMiddleware;
use Override;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Ssmiff\MezzioAuthenticationTokens\Console\IssueCommand;
use Ssmiff\MezzioAuthenticationTokens\Console\PruneCommand;
use Ssmiff\MezzioAuthenticationTokens\Console\RevokeCommand;
use Ssmiff\MezzioAuthenticationTokens\DbalTokenRepository;
use Ssmiff\MezzioAuthenticationTokens\Jwt\JwtCodec;
use Ssmiff\MezzioAuthenticationTokens\AuthServiceId;
use Ssmiff\MezzioAuthenticationTokens\Support\Settings;
use Ssmiff\MezzioAuthenticationTokens\TokenAuthentication;
use Ssmiff\MezzioAuthenticationTokens\TokenIssuer;
use Ssmiff\MezzioAuthenticationTokens\TokenRepository;
use Ssmiff\MezzioContainerHelpers\Services;
use UnexpectedValueException;

use function sprintf;

/** Builds every service of the module; the requested name selects which. */
final readonly class ServicesFactory implements FactoryInterface
{
    #[Override]
    public function __invoke(ContainerInterface $container, string $requestedName, ?array $options = null): object
    {
        $settings = Settings::from($container);

        return match ($requestedName) {
            TokenRepository::class, DbalTokenRepository::class => new DbalTokenRepository(
                Services::get($container, Connection::class, AuthServiceId::CONNECTION),
                $settings->table(),
            ),
            JwtCodec::class => new JwtCodec(
                $settings->key(),
                $settings->issuer(),
                Services::get($container, ClockInterface::class, AuthServiceId::CLOCK),
            ),
            TokenIssuer::class => new TokenIssuer(
                Services::get($container, TokenRepository::class),
                Services::get($container, JwtCodec::class),
                Services::get($container, ClockInterface::class, AuthServiceId::CLOCK),
                $settings->ttl(),
            ),
            TokenAuthentication::class => new TokenAuthentication(
                Services::get($container, JwtCodec::class),
                Services::get($container, TokenRepository::class),
                Services::get($container, ResponseFactoryInterface::class),
                Services::get($container, ClockInterface::class, AuthServiceId::CLOCK),
                $settings->touchInterval(),
            ),
            AuthServiceId::MIDDLEWARE => new AuthenticationMiddleware(
                Services::get($container, TokenAuthentication::class),
            ),
            IssueCommand::class => new IssueCommand(Services::get($container, TokenIssuer::class)),
            RevokeCommand::class => new RevokeCommand(Services::get($container, TokenIssuer::class)),
            PruneCommand::class => new PruneCommand(
                Services::get($container, TokenRepository::class),
                Services::get($container, ClockInterface::class, AuthServiceId::CLOCK),
            ),
            default => throw new UnexpectedValueException(sprintf('No factory for "%s".', $requestedName)),
        };
    }
}
