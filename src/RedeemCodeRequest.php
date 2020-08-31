<?php

namespace Francerz\OAuth2;

use Francerz\Http\MediaTypes;
use Francerz\Http\Methods;
use Francerz\Http\Request;
use Francerz\Http\UrlEncodedParams;
use Psr\Http\Message\RequestInterface;

class RedeemCodeRequest
{
    private $authClient;
    private $code;

    public function __construct(AuthClient $authClient = null, string $code = null)
    {
        $this->authClient = $authClient;
        $this->code = $code;
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
            'client_id' => $this->authClient->getClientId()
        ));

        if (false) {
            $request = $request->withAuthorizationHeader(
                'Basic',
                $this->authClient->getClientId() . ':' .
                $this->authClient->getClientSecret()
            );
        } else {
            $requestBody['client_secret'] = $this->authClient->getClientSecret();
        }
        $request = $request->withBody($requestBody->getStringStream());
        $request = $request->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED);

        return $request;
    }
}