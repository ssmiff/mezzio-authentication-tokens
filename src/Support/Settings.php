<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Support;

use InvalidArgumentException;
use Psr\Container\ContainerInterface;
use Ssmiff\MezzioAuthenticationTokens\TokensTable;

use function is_array;
use function is_int;
use function is_string;
use function sprintf;
use function strlen;

/**
 * The `authentication_tokens` section of the application config.
 *
 * @psalm-suppress MixedAssignment config values are mixed until checked
 */
final readonly class Settings
{
    /** @param array<array-key, mixed> $values */
    private function __construct(private array $values) {}

    public static function from(ContainerInterface $container): self
    {
        $config = $container->get('config');
        $values = is_array($config) ? ($config['authentication_tokens'] ?? []) : [];

        return new self(is_array($values) ? $values : []);
    }

    public function connection(): ?string
    {
        return $this->string('connection');
    }

    /** @return non-empty-string */
    public function key(): string
    {
        $key = $this->string('key');

        if ($key === null || $key === '' || strlen($key) < 32) {
            throw self::invalid('key', 'a string of at least 32 bytes');
        }

        return $key;
    }

    /** @return non-empty-string */
    public function issuer(): string
    {
        $issuer = $this->string('issuer');

        return $issuer === null || $issuer === '' ? 'authentication-tokens' : $issuer;
    }

    /** @return non-empty-string */
    public function table(): string
    {
        return TokensTable::name($this->string('table') ?? TokensTable::DEFAULT_NAME);
    }

    /** @return positive-int|null */
    public function ttl(): ?int
    {
        $ttl = $this->int('ttl');

        if ($ttl !== null && $ttl < 1) {
            throw self::invalid('ttl', 'a positive number of seconds, or null for tokens that never expire');
        }

        return $ttl;
    }

    /** @return int<0, max> */
    public function touchInterval(): int
    {
        $interval = $this->int('touch_interval') ?? 60;

        if ($interval < 0) {
            throw self::invalid('touch_interval', 'zero or a positive number of seconds');
        }

        return $interval;
    }

    private function string(string $key): ?string
    {
        $value = $this->values[$key] ?? null;

        return match (true) {
            $value === null => null,
            is_string($value) => $value,
            default => throw self::invalid($key, 'a string'),
        };
    }

    private function int(string $key): ?int
    {
        $value = $this->values[$key] ?? null;

        return match (true) {
            $value === null => null,
            is_int($value) => $value,
            default => throw self::invalid($key, 'an integer'),
        };
    }

    private static function invalid(string $key, string $expected): InvalidArgumentException
    {
        return new InvalidArgumentException(sprintf('Config "authentication_tokens.%s" must be %s.', $key, $expected));
    }
}
