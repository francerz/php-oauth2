<?php

namespace Francerz\OAuth2;

use Francerz\Http\Client as HttpClient;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use ReflectionFunction;

class AuthClient
{
    private $clientId; // string
    private $clientSecret; // string
    private $authorizationEndpoint; // UriInterface
    private $tokenEndpoint; // UriInterface

    private $checkStateHandler; // callback

    public function __construct(
        ?string $clientId = null,
        ?string $clientSecret = null,
        UriInterface $tokenEndpoint = null,
        UriInterface $authorizationEndpoint = null
    ) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->authorizationEndpoint = $authorizationEndpoint;
    }

    public function withClientId(string $clientId)
    {
        $new = clone $this;
        $new->clientId = $clientId;
        return $new;
    }

    public function getClientId() : string
    {
        return $this->clientId;
    }

    public function withClientSecret(string $clientSecret)
    {
        $new = clone $this;
        $new->clientSecret = $clientSecret;
        return $new;
    }
    
    public function getClientSecret() : string
    {
        return $this->clientSecret;
    }

    public function withAuthorizationEndpoint(UriInterface $authorizationEndpoint)
    {
        $new = clone $this;
        $new->authorizationEndpoint = $authorizationEndpoint;
        return $new;
    }

    public function getAuthorizationEndpoint() : UriInterface
    {
        return $this->authorizationEndpoint;
    }

    public function withTokenEndpoint(UriInterface $tokenEndpoint)
    {
        $new = clone $this;
        $new->tokenEndpoint = $tokenEndpoint;
        return $new;
    }

    public function getTokenEndpoint() : UriInterface
    {
        return $this->tokenEndpoint;
    }

    public function setCheckStateHandler(callable $handler)
    {
        $rf = new ReflectionFunction($handler);

        $retType = $rf->getReturnType();
        if ($retType->getName() !== 'bool') {
            throw new InvalidArgumentException('Function return type must be \'bool\'.');
        }

        $args = $rf->getParameters();
        if (count($args) < 1 || $args[0]->getType()->getName() !== 'string') {
            throw new InvalidArgumentException('Function must contain one parameter type \'string\' for $state.');
        }

        $this->checkStateHandler = $handler;
    }

    public function handleAuthCode(ServerRequestInterface $request)
    {
        $params = $request->getQueryParams();

        if (array_key_exists('error', $params)) {
            throw new \Exception("{$params['error']}:{$params['error_description']}");
        }

        if (array_key_exists('state', $params)) {
            $csh = $this->checkStateHandler;
            if (isset($csh) && !$csh($params['state'])) {
                throw new \Exception('Failed state matching.');
            }
        }

        if (!array_key_exists('code', $params)) {
            throw new \Exception('Missing \'code\' parameter.');
        }

        $code = $params['code'];
        $redeemReq = new RedeemCodeRequest($this, $code);
        $redeemReqReq = $redeemReq->getRequest();

        $client = new HttpClient();
        $resp = $client->send($redeemReqReq);

        
    }
}