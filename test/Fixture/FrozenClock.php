<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Test\Fixture;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Override;
use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $now;

    public function __construct()
    {
        $this->now = new DateTimeImmutable('2026-10-27 12:00:00', new DateTimeZone('UTC'));
    }

    #[Override]
    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function advance(string $interval): void
    {
        $this->now = $this->now->add(new DateInterval($interval));
    }
}
