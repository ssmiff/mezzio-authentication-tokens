<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Support;

use DateTimeImmutable;
use DateTimeZone;
use Override;
use Psr\Clock\ClockInterface;

/** UTC, which is what the api_tokens dates are stored in. */
final readonly class SystemClock implements ClockInterface
{
    #[Override]
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
