<?php

namespace Francerz\OAuth2\Flow;

use Francerz\Http\Helpers\UriHelper;
use Francerz\Http\Request;
use Francerz\OAuth2\Roles\AuthClient;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

class AuthorizationCodeRequest
{
    private $authClient; // AuthClient
    private $scopes = array(); // array
    private $redirectUri; // UriInterface
    private $state; // string

    public function __construct(
        AuthClient $authClient = null
    ) {
        $this->authClient = $authClient;
    }

    public function getAuthClient() : AuthClient
    {
        return $this->authClient;
    }

    public function withAuthClient(AuthClient $authClient) : AuthorizationCodeRequest
    {
        $new = clone $this;
        $new->authClient = $authClient;
        return $new;
    }

    public function getScopes() : array
    {
        return $this->scopes;
    }

    public function withAddedScope($scope_or_scopes) : AuthorizationCodeRequest
    {
        $new = clone $this;
        if (is_array($scope_or_scopes)) {
            foreach ($scope_or_scopes as $s) {
                $new->scopes[] = $s;
            }
            return $new;
        }
        $new->scopes[] = $scope_or_scopes;
        return $new;
    }

    public function withRedirectUri(UriInterface $redirectUri) : AuthorizationCodeRequest
    {
        $new = clone $this;
        $new->redirectUri = $redirectUri;
        return $new;
    }
    public function getRedirectUri() : UriInterface
    {
        return $this->redirectUri;
    }

    public function withState(string $state)
    {
        $new = clone $this;
        $new->state = $state;
        return $new;
    }
    public function getState() : string
    {
        return $this->state;
    }

    public function getRequestUri() : UriInterface
    {
        if (!isset($this->authClient)) {
            throw new \Exception("AuthClient not sets");
        }
        $params = [
            'response_type' => 'code',
            'client_id' => $this->authClient->getClientId()
        ];

        if (isset($this->redirectUri)) {
            $params['redirect_uri'] = (string)$this->redirectUri;
        }
        if (!empty($this->scope)) {
            $params['scope'] = join(' ', $this->scopes);
        }
        if (isset($this->state)) {
            $params['state'] = $this->state;
        }

        $uri = $this->authClient->getAuthorizationEndpoint();
        $uri = UriHelper::withQueryParams($uri, $params);
        
        return $uri;
    }
}