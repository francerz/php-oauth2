<?php

namespace Francerz\OAuth2\Client;

use Francerz\Http\Constants\MediaTypes;
use Francerz\Http\Constants\Methods;
use Francerz\Http\Headers\BasicAuthorizationHeader;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\MessageHelper;
use Francerz\Http\Tools\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\TokenRequestGrantTypes;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use Psr\Http\Client\ClientInterface as HttpClient;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class AuthClient
{
    private $httpFactory;

    private $clientId; // string
    private $clientSecret; // string
    private $authorizationEndpoint; // UriInterface
    private $tokenEndpoint; // UriInterface
    private $callbackEndpoint; // UriInterface

    private $checkStateHandler; // callback

    private $accessToken;

    private $preferBodyAuthenticationFlag = false;

    public function __construct(
        HttpFactoryManager $httpFactory,
        string $clientId = '',
        string $clientSecret = '',
        $tokenEndpoint = null,
        $authorizationEndpoint = null,
        $callbackEndpoint = null
    ) {
        $this->httpFactory = $httpFactory;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        if (is_string($tokenEndpoint)) {
            $tokenEndpoint = $httpFactory->getUriFactory()
                ->createUri($tokenEndpoint);
        }
        if ($tokenEndpoint instanceof UriInterface) {
            $this->tokenEndpoint = $tokenEndpoint;
        }

        if (is_string($authorizationEndpoint)) {
            $authorizationEndpoint = $httpFactory->getUriFactory()
                ->createUri($authorizationEndpoint);
        }
        if ($authorizationEndpoint instanceof UriInterface) {
            $this->authorizationEndpoint = $authorizationEndpoint;
        }

        if (is_string($callbackEndpoint)) {
            $callbackEndpoint = $httpFactory->getUriFactory()
                ->createUri($callbackEndpoint);
        }
        if ($callbackEndpoint instanceof UriInterface) {
            $this->callbackEndpoint = $callbackEndpoint;
        }
    }

    #region Accessors
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

    public function withAccessToken(AccessToken $accessToken) : AuthClient
    {
        $new = clone $this;
        $new->accessToken = $accessToken;
        return $new;
    }

    public function getAccessToken() : ?AccessToken
    {
        return $this->accessToken;
    }

    public function preferBodyAuthentication(bool $prefer)
    {
        $this->preferBodyAuthenticationFlag = $prefer;
    }

    public function isBodyAuthenticationPreferred() : bool
    {
        return $this->preferBodyAuthenticationFlag;
    }

    public function getHttpFactory() : HttpFactoryManager
    {
        return $this->httpFactory;
    }
    #endregion

    public function setCheckStateHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], 'bool')) {
            throw new InvalidArgumentException('Funtion expected signature is: (string $state) : bool');
        }

        $this->checkStateHandler = $handler;
    }

    public function getAuthorizationCodeRequestUri(array $scopes, string $state) : UriInterface
    {
        $authCodeReq = new AuthorizationCodeRequest($this);
        $authCodeReq = $authCodeReq
            ->withAddedScope($scopes)
            ->withState($state);
        return $authCodeReq->getRequestUri();
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

    public function handleAuthCodeRequest(RequestInterface $request, HttpClient $httpClient) : ?AccessToken
    {
        $redeemReqReq = $this->getRedeemAuthCodeRequest($request);

        $response = $httpClient->sendRequest($redeemReqReq);

        return $this->accessToken = $this->getAccessTokenFromResponse($response);
    }

    public function getFetchAccessTokenWithRefreshTokenRequest(string $refreshToken) : RequestInterface
    {
        $bodyParams = array(
            'grant_type' => TokenRequestGrantTypes::REFRESH_TOKEN,
            'refresh_token' => $refreshToken
        );

        $requestFactory = $this->httpFactory->getRequestFactory();
        $request = $requestFactory->createRequest(Methods::GET, $this->tokenEndpoint);
        
        if ($this->preferBodyAuthenticationFlag) {
            $bodyParams['client_id'] = $this->getClientId();
            $bodyParams['client_secret'] = $this->getClientSecret();
        } else {
            $request = $request->withHeader(
                'Authorization',
                (string)new BasicAuthorizationHeader(
                    $this->getClientId(),
                    $this->getClientSecret()
                )
            );
        }

        $request = MessageHelper::withContent(
            $request,
            MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
            $bodyParams
        );

        return $request;
    }
}