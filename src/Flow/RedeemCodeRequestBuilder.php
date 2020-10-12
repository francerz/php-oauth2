<?php

namespace Francerz\OAuth2\Flow;

use Francerz\Http\MediaTypes;
use Francerz\Http\Methods;
use Francerz\Http\Request;
use Francerz\Http\UrlEncodedParams;
use Francerz\OAuth2\GrantTypes;
use Francerz\OAuth2\Roles\AuthClient;
use Psr\Http\Message\RequestInterface;

class RedeemCodeRequestBuilder
{
    private $authClient;
    private $code;

    public function __construct(AuthClient $authClient = null, string $code = null)
    {
        $this->authClient = $authClient;
        $this->code = $code;
    }

    public function withAuthClient(AuthClient $authClient)
    {
        $new = clone $this;
        $new->authClient = $authClient;
        return $new;
    }

    public function getAuthClient() : AuthClient
    {
        return $this->authClient;
    }

    public function withCode(string $code)
    {
        $new = clone $this;
        $new->code = $code;
        return $new;
    }

    public function getCode() : string
    {
        return $this->code;
    }

    public function getRequest() : RequestInterface
    {
        if (!isset($this->authClient)) {
            throw new \Exception('AuthClient not set');
        }
        if (!isset($this->code)) {
            throw new \Exception('Code not set');
        }

        $uri = $this->authClient->getTokenEndpoint();
        
        

        $request = new Request($uri);
        $request = $request->withMethod(Methods::POST);
        $requestBody = new UrlEncodedParams(array(
            'grant_type' => GrantTypes::AUTHORIZATION_CODE,
            'code' => $this->code,
        ));

        if ($this->authClient->isBodyAuthenticationPreferred()) {
            $requestBody['client_id'] = $this->authClient->getClientId();
            $requestBody['client_secret'] = $this->authClient->getClientSecret();
        } else {
            $request = $request->withAuthorizationHeader(
                'Basic',
                $this->authClient->getClientId() . ':' .
                $this->authClient->getClientSecret()
            );
        }
        
        $callbackEndpoint = $this->authClient->getCallbackEndpoint();
        if (isset($callbackEndpoint)) {
            $requestBody['redirect_uri'] = (string)$callbackEndpoint;
        }

        $request = $request->withBody($requestBody->getStringStream());
        $request = $request->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED);

        return $request;
    }
}