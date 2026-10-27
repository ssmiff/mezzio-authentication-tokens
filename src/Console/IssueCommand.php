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

use function is_array;
use function is_numeric;
use function is_string;

/** @psalm-suppress MixedAssignment console input is mixed until checked */
#[AsCommand('api-tokens:issue', 'Create an API token and print its JWT once.')]
final class IssueCommand extends Command
{
    public function __construct(private readonly TokenIssuer $issuer)
    {
        parent::__construct();
    }

    #[Override]
    protected function configure(): void
    {
        $this
            ->addArgument('user', InputArgument::REQUIRED, 'The user id the token authenticates as')
            ->addOption('name', null, InputOption::VALUE_REQUIRED, 'A label for the token', 'cli')
            ->addOption(
                'ability',
                'a',
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'An ability; repeat for several',
                ['*'],
            )
            ->addOption('tenant', null, InputOption::VALUE_REQUIRED, 'Bind the token to a tenant slug')
            ->addOption('ttl', null, InputOption::VALUE_REQUIRED, 'Lifetime in seconds; default from config');
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $user      = $input->getArgument('user');
        $name      = $input->getOption('name');
        $abilities = $input->getOption('ability');
        $tenant    = $input->getOption('tenant');
        $ttl       = $input->getOption('ttl');

        if (! is_string($user) || $user === '') {
            $output->writeln('<error>The user id must not be empty.</error>');

            return Command::INVALID;
        }

        $granted = [];

        foreach (is_array($abilities) ? $abilities : [] as $ability) {
            if (is_string($ability)) {
                $granted[] = $ability;
            }
        }

        $issued = $this->issuer->issue(
            $user,
            is_string($name) ? $name : 'cli',
            $granted === [] ? ['*'] : $granted,
            is_string($tenant) && $tenant !== '' ? $tenant : null,
            is_numeric($ttl) ? (int) $ttl : null,
        );

        $output->writeln('<info>Token ' . $issued->token->id . ' created. It will not be shown again:</info>');
        $output->writeln($issued->jwt);

        return Command::SUCCESS;
    }
}
