<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Factory;

use Laminas\ServiceManager\Factory\FactoryInterface;
use Override;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Ssmiff\MezzioAuthenticationTokens\Support\SystemClock;

/** Uses the application's PSR-20 clock when it has one. */
/** @psalm-suppress MixedAssignment a container service is mixed until checked */
final readonly class ClockFactory implements FactoryInterface
{
    #[Override]
    public function __invoke(
        ContainerInterface $container,
        string $requestedName,
        ?array $options = null,
    ): ClockInterface {
        $clock = $container->has(ClockInterface::class) ? $container->get(ClockInterface::class) : null;

        return $clock instanceof ClockInterface ? $clock : new SystemClock();
    }
}
