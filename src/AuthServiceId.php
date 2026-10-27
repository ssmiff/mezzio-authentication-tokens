<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens;

final class AuthServiceId
{
    /** The DBAL connection holding the api_tokens table. */
    public const string CONNECTION = 'authentication-tokens.connection';

    /** The PSR-20 clock the module uses: the application's, or UTC system time. */
    public const string CLOCK = 'authentication-tokens.clock';

    /** Middleware that authenticates a route with an API token; assign it to routes before the handler. */
    public const string MIDDLEWARE = 'authentication-tokens.authenticate';
}
