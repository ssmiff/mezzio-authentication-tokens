<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Test;

use Doctrine\DBAL\Connection;
use Laminas\Diactoros\ResponseFactory;
use Laminas\ServiceManager\ServiceManager;
use Override;
use PHPUnit\Framework\TestCase as PhpUnitTestCase;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Ssmiff\MezzioAuthenticationTokens\ConfigProvider;
use Ssmiff\MezzioAuthenticationTokens\AuthServiceId;
use Ssmiff\MezzioAuthenticationTokens\Support\Settings;
use Ssmiff\MezzioAuthenticationTokens\TokensTable;
use Ssmiff\MezzioAuthenticationTokens\Test\Fixture\FrozenClock;
use Ssmiff\MezzioContainerHelpers\ConfigProvider as HelpersConfigProvider;
use Ssmiff\MezzioDoctrine\ConfigProvider as DoctrineConfigProvider;

use function array_replace_recursive;
use function str_repeat;

/** @psalm-suppress MissingConstructor $clock is set by container() */
abstract class TestCase extends PhpUnitTestCase
{
    protected FrozenClock $clock;

    #[Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
    }

    /** @param array<string, mixed> $apiTokens */
    protected function container(array $apiTokens = []): ServiceManager
    {
        $doctrine = new DoctrineConfigProvider();
        $helpers  = new HelpersConfigProvider();
        $own      = new ConfigProvider();

        $config = array_replace_recursive($doctrine(), $own(), [
            'doctrine'   => [
                'default'     => 'tokens',
                'connections' => ['tokens' => ['driver' => 'pdo_sqlite', 'memory' => true]],
            ],
            'authentication_tokens' => ['connection' => 'tokens', 'key' => str_repeat('k', 32)],
        ], ['authentication_tokens' => $apiTokens]);

        $dependencies = array_replace_recursive(
            $doctrine->dependencies(),
            $helpers->dependencies(),
            $own->dependencies(),
        );

        /** @psalm-suppress MixedArgumentTypeCoercion merged dependency arrays are checked by the container */
        $container = new ServiceManager($dependencies);
        $container->setService('config', $config);
        $container->setService(ClockInterface::class, $this->clock);
        $container->setService(ResponseFactoryInterface::class, new ResponseFactory());

        $this->createTable($container->get(AuthServiceId::CONNECTION), Settings::from($container)->table());

        return $container;
    }

    /** @param non-empty-string $table */
    private function createTable(mixed $connection, string $table): void
    {
        self::assertInstanceOf(Connection::class, $connection);

        foreach ($connection->getDatabasePlatform()->getCreateTableSQL(TokensTable::create($table)) as $sql) {
            $connection->executeStatement($sql);
        }
    }
}
