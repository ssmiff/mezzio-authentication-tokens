<?php

declare(strict_types=1);

namespace Ssmiff\MezzioAuthenticationTokens\Test\Fixture;

use Laminas\Diactoros\Response\EmptyResponse;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RecordingHandler implements RequestHandlerInterface
{
    private ?ServerRequestInterface $request = null;

    public function lastRequest(): ?ServerRequestInterface
    {
        return $this->request;
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->request = $request;

        return new EmptyResponse(204);
    }
}
