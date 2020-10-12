<?php

namespace Francerz\OAuth2\Roles;

use Francerz\Http\Base\MessageBase;
use Francerz\Http\Client as HttpClient;
use Francerz\Http\Helpers\MessageHelper;
use Francerz\Http\Helpers\UriHelper;
use Francerz\Http\MediaTypes;
use Francerz\Http\Request;
use Francerz\Http\UrlEncodedParams;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\Flow\RedeemCodeRequestBuilder;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class AuthClient
{
    private $clientId; // string
    private $clientSecret; // string
    private $authorizationEndpoint; // UriInterface
    private $tokenEndpoint; // UriInterface
    private $callbackEndpoint; // UriInterface

    private $checkStateHandler; // callback

    private $access_token;

    private $preferBodyAuthenticationFlag = false;

    public function __construct(
        ?string $clientId = null,
        ?string $clientSecret = null,
        UriInterface $tokenEndpoint = null,
        UriInterface $authorizationEndpoint = null,
        UriInterface $callbackEndpoint = null
    ) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->authorizationEndpoint = $authorizationEndpoint;
        $this->callbackEndpoint = $callbackEndpoint;
    }

    public function withClientId(string $clientId) : AuthClient
    {
        $new = clone $this;
        $new->clientId = $clientId;
        return $new;
    }

    public function getClientId() : ?string
    {
        return $this->clientId;
    }

    public function withClientSecret(string $clientSecret) : AuthClient
    {
        $new = clone $this;
        $new->clientSecret = $clientSecret;
        return $new;
    }
    
    public function getClientSecret() : ?string
    {
        return $this->clientSecret;
    }

    public function withAuthorizationEndpoint(UriInterface $authorizationEndpoint) : AuthClient
    {
        $new = clone $this;
        $new->authorizationEndpoint = $authorizationEndpoint;
        return $new;
    }

    public function getAuthorizationEndpoint() : ?UriInterface
    {
        return $this->authorizationEndpoint;
    }

    public function withTokenEndpoint(UriInterface $tokenEndpoint) : AuthClient
    {
        $new = clone $this;
        $new->tokenEndpoint = $tokenEndpoint;
        return $new;
    }

    public function getTokenEndpoint() : ?UriInterface
    {
        return $this->tokenEndpoint;
    }

    public function withCallbackEndpoint(UriInterface $callbackEndpoint) : AuthClient
    {
        $new = clone $this;
        $new->callbackEndpoint = $callbackEndpoint;
        return $new;
    }

    public function getCallbackEndpoint() : ?UriInterface
    {
        return $this->callbackEndpoint;
    }

    public function withAccessToken(AccessToken $access_token) : AuthClient
    {
        $new = clone $this;
        $new->access_token = $access_token;
        return $new;
    }

    public function getAccessToken() : ?AccessToken
    {
        return $this->access_token;
    }

    public function setCheckStateHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], 'bool')) {
            throw new InvalidArgumentException('Funtion expected signature is: (string $state) : bool');
        }

        $this->checkStateHandler = $handler;
    }

    public function preferBodyAuthentication(bool $prefer)
    {
        $this->preferBodyAuthenticationFlag = $prefer;
    }

    public function isBodyAuthenticationPreferred() : bool
    {
        return $this->preferBodyAuthenticationFlag;
    }

    public function getRedeemAuthCodeRequest(RequestInterface $request) : RequestInterface
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
        $redeemReq = new RedeemCodeRequestBuilder($this, $code);
        return $redeemReq->getRequest();
    }

    public function getAccessTokenFromResponse(ResponseInterface $response) : AccessToken
    {
        if ($response->getStatusCode() >= 400) {
            $resp = MessageHelper::getContent($response);
            throw new \Exception($resp->error.': '.PHP_EOL.$resp->error_description);
        }

        return AccessToken::fromHttpMessage($response);
    }

    public function handleAuthCodeRequest(RequestInterface $request) : ?AccessToken
    {
        $redeemReqReq = $this->getRedeemAuthCodeRequest($request);

        $client = new HttpClient();
        $response = $client->send($redeemReqReq);

        return $this->access_token = $this->getAccessTokenFromResponse($response);
    }

    public function getFetchAccessTokenWithRefreshTokenRequest(string $refreshToken) : RequestInterface
    {
        $bodyParams = new UrlEncodedParams(array(
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken
        ));

        $request = new Request($this->tokenEndpoint);

        if ($this->preferBodyAuthenticationFlag) {
            $bodyParams['client_id'] = $this->getClientId();
            $bodyParams['client_secret'] = $this->getClientSecret();
        } else {
            $request = $request->withAuthorizationHeader(
                'Basic',
                $this->getClientId() . ':' .
                $this->getClientSecret()
            );
        }

        $request = $request
            ->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED)
            ->withBody($bodyParams->getStringStream());

        return $request;
    }
}