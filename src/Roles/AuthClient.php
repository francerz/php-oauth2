<?php

namespace Francerz\OAuth2\Roles;

use Francerz\Http\Client as HttpClient;
use Francerz\Http\Helpers\UriHelper;
use Francerz\OAuth2\Flow\RedeemCodeRequest;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

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
        if (!Functions::testSignature($handler, ['string'], 'bool')) {
            throw new InvalidArgumentException('Funtion expected signature is: (string $state) : bool');
        }

        $this->checkStateHandler = $handler;
    }

    public function handleAuthCodeRequest(RequestInterface $request)
    {
        $params = UriHelper::getQueryParams($request->getUri());

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