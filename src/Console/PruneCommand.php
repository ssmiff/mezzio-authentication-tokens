<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Console;

use DateInterval;
use Override;
use Psr\Clock\ClockInterface;
use Ssmiff\MezzioAuthenticationTokens\TokenRepository;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use function is_numeric;

/** @psalm-suppress MixedAssignment console input is mixed until checked */
#[AsCommand('api-tokens:prune', 'Delete tokens that expired or were revoked some days ago.')]
final class PruneCommand extends Command
{
    public function __construct(
        private readonly TokenRepository $tokens,
        private readonly ClockInterface $clock,
    ) {
        parent::__construct();
    }

    #[Override]
    protected function configure(): void
    {
        $this->addOption(
            'days',
            null,
            InputOption::VALUE_REQUIRED,
            'Keep tokens that ended within this many days',
            '30',
        );
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $days  = $input->getOption('days');
        $count = $this->tokens->prune(
            $this->clock->now()->sub(new DateInterval('P' . (is_numeric($days) ? (int) $days : 30) . 'D')),
        );

        $output->writeln('Deleted ' . $count . ' token(s).');

        return Command::SUCCESS;
    }
}
