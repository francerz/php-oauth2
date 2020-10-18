<?php

namespace Francerz\OAuth2\Roles;

use Francerz\Http\Constants\MediaTypes;
use Francerz\Http\Constants\StatusCodes;
use Francerz\Http\Headers\BasicAuthorizationHeader;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\MessageHelper;
use Francerz\Http\Tools\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\Exceptions\AuthServerException;
use Francerz\OAuth2\Exceptions\InvalidRequestException;
use Francerz\OAuth2\Exceptions\UnavailableResourceOwnerException;
use Francerz\OAuth2\GrantTypes;
use Francerz\OAuth2\AuthCodeInterface;
use Francerz\OAuth2\AuthErrorCodes;
use Francerz\OAuth2\ClientInterface;
use Francerz\OAuth2\RefreshTokenInterface;
use Francerz\OAuth2\ResourceOwnerInterface;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class AuthServer
{
    private $httpFactory;

    private $createAuthorizationCodeHandler;
    private $createAccessTokenHandler;
    private $findAuthorizationCodeHandler;
    private $findClientHandler;
    private $findResourceOwnerHandler;
    private $findRefreshTokenHandler;
    private $getResourceOwnerHandler;
    private $updateAuthorizationCodeRedeemTimeHandler;

    private $client;
    private $resourceOwner;
    private $scopes;

    private $authorizationCode;

    public function __construct(HttpFactoryManager $httpFactory)
    {
        $this->httpFactory = $httpFactory;
    }

    #region set handlers methods
    /**
     * Sets a callback handler to retrieve a ClientInterface object from a
     * client_id.
     *
     * @param callable $handler (string $client_id) : ClientInterface
     * @return void
     */
    public function setFindClientHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], ClientInterface::class)) {
            throw new InvalidArgumentException('Function expected signature is: (string $client_id) : ClientInterface');
        }

        $this->findClientHandler = $handler;
    }

    /**
     * Sets a callaback handler to get a ResourceOwnerInterface object for
     * current authorization server session.
     *
     * @param callable $handler () : ResourceOwnerInterface
     * @return void
     */
    public function setGetResourceOwnerHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [], ResourceOwnerInterface::class)) {
            throw new InvalidArgumentException('Function expected signature is: () : ResourceOwnerInterface');
        }

        $this->getResourceOwnerHandler = $handler;
    }

    /**
     * Sets a callback handler to get a Authorization Code string given with
     * an ClientInterface object, ResourceOwnerInterface object and scopes.
     *
     * @param callable $handler (ClientInterface $client, ResourceOwnerInterface $owner, string scope) : string
     * @return void
     */
    public function setCreateAuthorizationCodeHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [ClientInterface::class, ResourceOwnerInterface::class, 'string', UriInterface::class], 'string')) {
            throw new InvalidArgumentException('Function expected signature is: (ClientInterface $client, ResourceOwnerInterface $owner, string scope, UriInterface $redirect_uri) : string');
        }

        $this->createAuthorizationCodeHandler = $handler;
    }

    /**
     * Undocumented function
     *
     * @param callable $handler (string $code) : AuthCodeInterface
     */
    public function setFindAuthorizationCodeHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], AuthCodeInterface::class)) {
            throw new InvalidArgumentException('Function expected signature is: (string $code) : AuthCodeInterface');
        }

        $this->findAuthorizationCodeHandler = $handler;
    }

    /**
     * @param callable $handler (AuthCodeInterface $authCode) : void
     */
    public function setUpdateAuthorizationCodeRedeemTimeHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AuthCodeInterface::class])) {
            throw new InvalidArgumentException('Function expected signature is: (AuthCodeInterface $authCode) : void');
        }

        $this->updateAuthorizationCodeRedeemTimeHandler = $handler;
    }

    /**
     * Undocumented function
     *
     * @param callable $handler (ClientInterface $client, ResourceOwnerInterface $owner, string $scopes)
     * @return void
     */
    public function setCreateAccessTokenHandler(callable $handler)
    {
        if (!Functions::testSignature(
            $handler,
            [ClientInterface::class, ResourceOwnerInterface::class, 'string'],
            AccessToken::class)
        ) {
            throw new InvalidArgumentException('Function expected signature is: (ClientInterface $client, ResourceOwnerInterface $owner, string $scope) : AccessToken');
        }

        $this->createAccessTokenHandler = $handler;
    }

    public function setFindResourceOwnerHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], ResourceOwnerInterface::class)) {
            throw new InvalidArgumentException('Function expected signature is: (string $ownerUniqueId) : ResourceOwnerInterface');
        }

        $this->findResourceOwnerHandler = $handler;
    }

    public function setFindRefreshTokenHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], RefreshTokenInterface::class)) {
            throw new InvalidArgumentException('Function expected signature is: (string $refreshToken) : RefreshTokenInterface');
        }

        $this->findRefreshTokenHandler = $handler;
    }
    #endregion

    public function handleAuthRequest(RequestInterface $request) : ResponseInterface
    {
        $response_type = UriHelper::getQueryParam($request->getUri(), 'response_type');

        switch($response_type) {
            case 'code':
                return $this->handleAuthRequestCode($request);
            default:
                $redirect_uri_str = UriHelper::getQueryParam($request->getUri(), 'redirect_uri');
                $redirect_uri = $this->httpFactory->getUriFactory()->createUri($redirect_uri_str);

                $state = UriHelper::getQueryParam($request->getUri(), 'state');
                $redirect_uri = UriHelper::withQueryParams($redirect_uri, array(
                    'state' => $state,
                    'error' => AuthErrorCodes::UNSUPPORTED_RESPONSE_TYPE
                ));


                $response = $this->httpFactory->getResponseFactory()->createResponse(StatusCodes::REDIRECT_FOUND);
                $response = $response->withHeader('Location', $redirect_uri);
                return $response;
        }
    }
    private function handleAuthRequestCode(RequestInterface $request) : ResponseInterface
    {
        $client_id = UriHelper::getQueryParam($request->getUri(), 'client_id');
        if (empty($client_id)) {
            throw new InvalidRequestException('Missing client_id.');
        }

        $fch = $this->findClientHandler;
        if (!is_callable($fch)) {
            throw new AuthServerException(
                'Callable findClientHandler not found.'.PHP_EOL.
                'Use '.static::class.'::setFindClientHandler() to initialize.'
            );
        }

        $this->client = $fch($client_id);
        if (!isset($this->client)) {
            throw new InvalidRequestException('Unknown client_id.');
        }

        $groh = $this->getResourceOwnerHandler;
        if (!is_callable($groh)) {
            throw new AuthServerException(
                'Callable getResourceOwnerHandler not found.'.PHP_EOL.
                'Use '.static::class.'::setGetResourceOwnerHandler() to initialize.'
            );
        }

        $this->resourceOwner = $groh();
        if (!isset($this->resourceOwner)) {
            throw new UnavailableResourceOwnerException('Resource owner not found.');
        }

        $scope = UriHelper::getQueryParam($request->getUri(), 'scope');
        $this->scopes = explode(' ', $scope);

        $cach = $this->createAuthorizationCodeHandler;
        if (!is_callable($cach)) {
            throw new AuthServerException(
                'Callable getAuthorizationCodeHandler not found.'.PHP_EOL.
                'Use '.static::class.'::setGetAuthorizationCodeHandler() to initialize.'
            );
        }

        $redirect_uri_str = UriHelper::getQueryParam($request->getUri(), 'redirect_uri');
        $redirect_uri = $this->httpFactory->getUriFactory()->createUri($redirect_uri_str);
        $state = UriHelper::getQueryParam($request->getUri(), 'state');

        $this->authorizationCode = $cach($this->client, $this->resourceOwner, $scope, $redirect_uri);

        $redirect_uri = UriHelper::withQueryParams($redirect_uri, array(
            'state' => $state,
            'code' => $this->authorizationCode
        ));

        $response = $this->httpFactory->getResponseFactory()->createResponse(StatusCodes::REDIRECT_FOUND);
        $response = $response->withHeader('Location', $redirect_uri);

        return $response;
    }

    public function handleTokenRequest(RequestInterface $request) : ResponseInterface
    {
        $params = MessageHelper::getContent($request);

        if (empty($params)) {
            throw new \Exception('No parameters received');
        }

        if (!array_key_exists('grant_type', $params)) {
            throw new \Exception('No grant_type received.');
        }

        switch($params['grant_type']) {
            case GrantTypes::AUTHORIZATION_CODE:
                return $this->handleTokenRequestCode($request);
            case GrantTypes::REFRESH_TOKEN:
                return $this->handleTokenRequestRefreshToken($request);
        }
    }

    private function getClientCredentials(
        RequestInterface $request,
        ?string &$client_id = '',
        ?string &$client_secret = ''
    ) {
        $auth = MessageHelper::getAuthorizationHeader($request);

        if (isset($auth) && $auth instanceof BasicAuthorizationHeader) {
            $client_id = $auth->getUser();
            $client_secret = $auth->getPassword();
            return;
        }

        $params = MessageHelper::getContent($request);
        if (array_key_exists('client_id', $params)) {
            $client_id = $params['client_id'];
        }
        if (array_key_exists('client_secret', $params)) {
            $client_secret = $params['client_secret'];
        }
    }

    private function checkClientCredentials(RequestInterface $request)
    {
        $fch = $this->findClientHandler;
        if (!is_callable($fch)) {
            throw new AuthServerException('Callable findClientHandler not found.');
        }

        $this->getClientCredentials($request, $client_id, $client_secret);

        if (empty($client_id)) {
            throw new \Exception('Missing client_id.');
        }

        $this->client = $fch($client_id);
        if (!isset($this->client)) {
            throw new InvalidRequestException('Unknown client_id.');
        }

        if ($this->client->isConfidential()) {
            if (empty($client_secret)) {
                throw new \Exception('Missing client_secret.');
            }
            if ($this->client->getClientSecret() !== $client_secret) {
                throw new \Exception('Incorrect client credentials.');
            }
        }

        return true;
    }

    private function buildAccessTokenResponse(AccessToken $accessToken) : ResponseInterface
    {
        $response = $this->httpFactory->getResponseFactory()->createResponse(StatusCodes::SUCCESS_OK);
        $response = $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
        $response = MessageHelper::withContent($response, MediaTypes::APPLICATION_JSON, $accessToken);
        
        return $response;
    }

    private function handleTokenRequestCode(RequestInterface $request) : ResponseInterface
    {
        #region Callable checks

        $fach = $this->findAuthorizationCodeHandler;
        if (!is_callable($fach)) {
            throw new \Exception('Callable findAuthorizationCodeHandler not found.');
        }

        $froh = $this->findResourceOwnerHandler;
        if (!is_callable($froh)) {
            throw new \Exception('Callable findResourceOwnerHandler not found.');
        }

        $uacrth = $this->updateAuthorizationCodeRedeemTimeHandler;
        if (!is_callable($uacrth)) {
            throw new \Exception('Callable updateAuthorizationCodeRedeemTimeHandler not found.');
        }
        
        $cath = $this->createAccessTokenHandler;
        if (!is_callable($cath)) {
            throw new \Exception('Callable createAccessTokenHandler not found.');
        }
        #endregion

        $this->checkClientCredentials($request);
       
        $params = MessageHelper::getContent($request);

        if (!array_key_exists('code', $params)) {
            throw new \Exception('Missing code parameter.');
        }
        $code = $params['code'];
        $authCode = $fach($code);

        if ($authCode->getClientId() != $this->client->getClientId()) {
            throw new \Exception('Authorization code not matching with client credentials.');
        }
        if ($authCode->isUsed()) {
            throw new \Exception('Authorization code already used.');
        }
        if ($authCode->isExpired()) {
            throw new \Exception('Authorization code expired.');
        }

        $resourceOwner = $froh($authCode->getOwnerId());

        $authCode = $authCode->withRedeemTime(time());
        $uacrth($authCode);

        $accessToken = $cath($this->client, $resourceOwner, $authCode->getScope());

        $response = $this->buildAccessTokenResponse($accessToken);

        return $response;
    }

    private function handleTokenRequestRefreshToken(RequestInterface $request) : ResponseInterface
    {
        $this->checkClientCredentials($request);

        $frth = $this->findRefreshTokenHandler;
        if (!is_callable($frth)) {
            throw new \Exception('Callable findRefreshTokenHandler not found.');
        }
        $froh = $this->findResourceOwnerHandler;
        if (!is_callable($froh)) {
            throw new \Exception('Callable findResourceOwnerHandler not found.');
        }
        $cath = $this->createAccessTokenHandler;
        if (!is_callable($cath)) {
            throw new \Exception('Callable createAccessTokenHandler not found.');
        }
        
        $params = MessageHelper::getContent($request);

        if (!array_key_exists('refresh_token', $params)) {
            throw new \Exception('Missing refresh_token.');
        }

        $refreshToken = $frth($params['refresh_token']);
        if (!isset($refreshToken)) {
            throw new \Exception('Invalid refresh_token.');
        }

        $resourceOwner = $froh($refreshToken->getOwnerId());
        if (!isset($resourceOwner)) {
            throw new \Exception('Unknown Resource Owner.');
        }

        $accessToken = $cath($this->client, $resourceOwner, $refreshToken->getScope());

        $response = $this->buildAccessTokenResponse($accessToken);

        return $response;
    }
}