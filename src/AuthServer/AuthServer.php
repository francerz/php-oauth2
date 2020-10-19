<?php

namespace Francerz\OAuth2\AuthServer;

use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\OAuth2\AuthServer\Handlers\AuthorizeRequestHandler;
use Francerz\OAuth2\AuthServer\Handlers\TokenRequestHandler;

class AuthServer
{
    private $httpFactory;

    public function __construct(HttpFactoryManager $httpFactory)
    {
        $this->httpFactory = $httpFactory;
    }

    public function getHttpFactory() : HttpFactoryManager
    {
        return $this->httpFactory;
    }

    public function createAuthorizeRequestHandler() : AuthorizeRequestHandler
    {
        return new AuthorizeRequestHandler($this);
    }

    public function createTokenRequestHandler() : TokenRequestHandler
    {
        return new TokenRequestHandler($this);
    }
}