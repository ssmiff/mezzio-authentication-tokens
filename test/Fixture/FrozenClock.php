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

    /**
     * Noon UTC on 2026-10-27, expressed in the given timezone.
     *
     * @param non-empty-string $timezone
     */
    public function __construct(string $timezone = 'UTC')
    {
        $this->now = new DateTimeImmutable('2026-10-27 12:00:00', new DateTimeZone('UTC'))
            ->setTimezone(new DateTimeZone($timezone));
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
