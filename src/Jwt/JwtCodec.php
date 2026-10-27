<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Jwt;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Psr\Clock\ClockInterface;
use Ssmiff\MezzioAuthenticationTokens\Token;
use Throwable;

use function is_string;

/**
 * Signs and verifies the JWT given to clients (HS256). The JWT identifies a token row; it is not trusted for
 * anything else, so a signature that checks out still fails once the row is revoked, expired or gone.
 */
final readonly class JwtCodec
{
    private Configuration $configuration;

    /**
     * @param non-empty-string $key at least 32 bytes
     * @param non-empty-string $issuer
     */
    public function __construct(string $key, private string $issuer, private ClockInterface $clock)
    {
        $this->configuration = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($key));
    }

    public function encode(Token $token): string
    {
        $builder = $this->configuration->builder()
            ->issuedBy($this->issuer)
            ->identifiedBy($token->id)
            ->relatedTo($token->userId)
            ->issuedAt($token->createdAt)
            ->withClaim('abilities', $token->abilities);

        if ($token->tenant !== null) {
            $builder = $builder->withClaim('tenant', $token->tenant);
        }

        if ($token->expiresAt instanceof DateTimeImmutable) {
            $builder = $builder->expiresAt($token->expiresAt);
        }

        return $builder->getToken($this->configuration->signer(), $this->configuration->signingKey())->toString();
    }

    /** @return string|null the token id (jti) when the signature, issuer and lifetime are valid */
    public function decode(string $jwt): ?string
    {
        if ($jwt === '') {
            return null;
        }

        try {
            $parsed = $this->configuration->parser()->parse($jwt);

            if (! $parsed instanceof Plain) {
                return null;
            }

            $valid = $this->configuration->validator()->validate(
                $parsed,
                new SignedWith($this->configuration->signer(), $this->configuration->verificationKey()),
                new IssuedBy($this->issuer),
                new LooseValidAt($this->clock),
            );

            /** @psalm-suppress MixedAssignment claims are mixed until checked */
            $id = $parsed->claims()->get('jti');

            return $valid && is_string($id) && $id !== '' ? $id : null;
        } catch (Throwable) {
            return null;
        }
    }
}
