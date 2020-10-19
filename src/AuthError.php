<?php

namespace Francerz\OAuth2;

use Francerz\Http\Constants\StatusCodes;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\UriHelper;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class AuthError
{
    private $httpFactory;

    private $error; // string
    private $errorDescription; // error
    private $errorUri; // UriInterface
    private $state; // string

    public function __construct(
        HttpFactoryManager $httpFactory,
        string $state,
        string $error,
        ?string $errorDescription = null,
        ?UriInterface $errorUri = null
    ) {
        $this->httpFactory = $httpFactory;
        $this->state = $state;
        $this->error = $error;
        $this->errorDescription = $errorDescription;
        $this->errorUri = $errorUri;
    }

    public function getErrorResponse()
    {
    }

    public function getErrorRedirect(UriInterface $redirectUri) : ResponseInterface
    {
        $redirectUri = UriHelper::withQueryParams($redirectUri, array(
            'state' => $this->state,
            'error' => $this->error,
            'error_description' => $this->errorDescription,
            'error_uri' => $this->errorUri
        ));

        $response = $this->httpFactory->getResponseFactory()
            ->createResponse(StatusCodes::REDIRECT_TEMPORARY_REDIRECT);
        $response = $response->withHeader('Location', (string)$redirectUri);

        return $response;
    }
}