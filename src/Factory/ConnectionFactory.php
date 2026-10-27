<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Factory;

use Doctrine\DBAL\Connection;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Override;
use Psr\Container\ContainerInterface;
use Ssmiff\MezzioAuthenticationTokens\Support\Settings;
use Ssmiff\MezzioContainerHelpers\Services;
use Ssmiff\MezzioDoctrine\Registry;

final readonly class ConnectionFactory implements FactoryInterface
{
    #[Override]
    public function __invoke(ContainerInterface $container, string $requestedName, ?array $options = null): Connection
    {
        return Services::get($container, Registry::class)->connection(Settings::from($container)->connection());
    }
}
