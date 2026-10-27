<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Test;

use Laminas\Diactoros\ServerRequest;
use Ssmiff\MezzioAuthenticationTokens\ConfigProvider;
use Ssmiff\MezzioAuthenticationTokens\Console\IssueCommand;
use Ssmiff\MezzioAuthenticationTokens\Console\PruneCommand;
use Ssmiff\MezzioAuthenticationTokens\Console\RevokeCommand;
use Ssmiff\MezzioAuthenticationTokens\TokenAuthentication;
use Ssmiff\MezzioAuthenticationTokens\TokenUser;
use Ssmiff\MezzioContainerHelpers\Services;
use Symfony\Component\Console\Tester\CommandTester;

use function array_keys;
use function explode;
use function trim;

final class ConsoleTest extends TestCase
{
    public function testEveryCommandIsRegisteredAndResolvable(): void
    {
        $container = $this->container();
        $commands  = new ConfigProvider()->commands();

        self::assertSame(['api-tokens:issue', 'api-tokens:revoke', 'api-tokens:prune'], array_keys($commands));

        foreach ($commands as $class) {
            self::assertInstanceOf($class, $container->get($class));
        }
    }

    public function testIssueThenRevoke(): void
    {
        $container = $this->container();
        $issue     = new CommandTester(Services::get($container, IssueCommand::class));

        self::assertSame(0, $issue->execute(['user' => 'u1', '--ability' => ['notes:read'], '--tenant' => 'acme']));

        $lines = explode("\n", trim($issue->getDisplay()));
        $jwt   = $lines[1];
        $id    = explode(' ', $lines[0])[1];

        $auth = Services::get($container, TokenAuthentication::class);
        $user = $auth->authenticate(new ServerRequest(headers: ['Authorization' => 'Bearer ' . $jwt]));
        self::assertInstanceOf(TokenUser::class, $user);
        self::assertSame(['notes:read'], $user->getRoles());

        $revoke = new CommandTester(Services::get($container, RevokeCommand::class));
        self::assertSame(0, $revoke->execute(['id' => $id]));
        self::assertNull($auth->authenticate(new ServerRequest(headers: ['Authorization' => 'Bearer ' . $jwt])));
        self::assertSame(1, $revoke->execute(['id' => $id]));
    }

    public function testRevokeNeedsExactlyOneTarget(): void
    {
        $revoke = new CommandTester(Services::get($this->container(), RevokeCommand::class));

        self::assertSame(2, $revoke->execute([]));
        self::assertSame(2, $revoke->execute(['id' => 'x', '--user' => 'u']));
    }

    public function testPruneReportsHowManyWereDeleted(): void
    {
        $prune = new CommandTester(Services::get($this->container(), PruneCommand::class));

        self::assertSame(0, $prune->execute([]));
        self::assertStringContainsString('Deleted 0 token(s).', $prune->getDisplay());
    }
}
