<?php

namespace Francerz\OAuth2;

use Psr\Http\Message\UriInterface;

class AuthClient
{
    private string $clientId;
    private string $clientSecret;
    private UriInterface $authorizationEndpoint;

    public function setClientId(string $clientId)
    {
        $this->clientId = $clientId;
    }

    public function getClientId() : string
    {
        return $this->clientId;
    }

    public function setClientSecret(string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }
    
    public function getClientSecret() : string
    {
        return $this->clientSecret;
    }

    public function getAuthorizationEndpoint() : UriInterface
    {
        return $this->authorizationEndpoint;
    }

    public function setAuthorizationEndpoint(UriInterface $authorizationEndpoint)
    {
        $this->authorizationEndpoint = $authorizationEndpoint;
    }
}