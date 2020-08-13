<?php

namespace Francerz\OAuth2;

use Psr\Http\Message\UriInterface;

class AuthorizationCodeRequest
{
    private AuthClient $authClient;
    private array $scopes = array();
    private UriInterface $redirectUri;
    private string $state;

    public function getAuthClient() : AuthClient
    {
        return $this->authClient;
    }

    public function setAuthClient(AuthClient $authClient)
    {
        $this->authClient = $authClient;
    }

    public function getScopes() : array
    {
        return $this->scopes;
    }

    public function addScope($scope_or_scopes)
    {
        if (is_array($scope_or_scopes)) {
            foreach ($scope_or_scopes as $s) {
                $this->addScope($s);
            }
            return;
        }
        $this->scopes[] = $scope_or_scopes;
    }

    public function setRedirectUri(UriInterface $redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }
    public function getRedirectUri() : UriInterface
    {
        return $this->redirectUri;
    }

    public function setState(string $state)
    {
        $this->state = $state;
    }
    public function getState() : string
    {
        return $this->state;
    }

    public function getRequestUri() : UriInterface
    {
        $params = [
            'response_type' => 'code',
            'client_id' => $this->authClient->getClientId()
        ];

        if (isset($this->redirectUri)) {
            $params['redirect_uri'] = $this->redirectUri;
        }
        if (!empty($this->scope)) {
            $params['scope'] = join(' ', $this->scopes);
        }
        if (isset($this->state)) {
            $params['state'] = $this->state;
        }

        $uri = $this->authClient->getAuthorizationEndpoint();
        $uri = $uri->withQueryParams($params);

        return $uri;
    }
}