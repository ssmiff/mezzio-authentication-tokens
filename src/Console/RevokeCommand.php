<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Console;

use Override;
use Ssmiff\MezzioAuthenticationTokens\TokenIssuer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use function is_string;

/** @psalm-suppress MixedAssignment console input is mixed until checked */
#[AsCommand('api-tokens:revoke', 'Revoke one token, or every token of a user or tenant.')]
final class RevokeCommand extends Command
{
    public function __construct(private readonly TokenIssuer $issuer)
    {
        parent::__construct();
    }

    #[Override]
    protected function configure(): void
    {
        $this
            ->addArgument('id', InputArgument::OPTIONAL, 'The token id')
            ->addOption('user', null, InputOption::VALUE_REQUIRED, 'Revoke every token of this user id')
            ->addOption('tenant', null, InputOption::VALUE_REQUIRED, 'Revoke every token bound to this tenant slug');
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $id     = $input->getArgument('id');
        $user   = $input->getOption('user');
        $tenant = $input->getOption('tenant');

        $targets = (is_string($id) ? 1 : 0) + (is_string($user) ? 1 : 0) + (is_string($tenant) ? 1 : 0);

        if ($targets !== 1) {
            $output->writeln('<error>Give exactly one of: a token id, --user or --tenant.</error>');

            return Command::INVALID;
        }

        $count = match (true) {
            is_string($id) => (int) $this->issuer->revoke($id),
            is_string($user) => $this->issuer->revokeForUser($user),
            default => $this->issuer->revokeForTenant((string) $tenant),
        };

        $output->writeln('Revoked ' . $count . ' token(s).');

        return $count > 0 ? Command::SUCCESS : Command::FAILURE;
    }
}
