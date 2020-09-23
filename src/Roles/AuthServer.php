<?php

namespace Francerz\OAuth2\Roles;

use Francerz\Http\Helpers\BodyHelper;
use Francerz\Http\Helpers\MessageHelper;
use Francerz\Http\Helpers\UriHelper;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Francerz\Http\Uri;
use Francerz\Http\Response;
use Francerz\Http\StatusCodes;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\Exceptions\AuthServerException;
use Francerz\OAuth2\Exceptions\InvalidRequestException;
use Francerz\OAuth2\Exceptions\UnavailableResourceOwnerException;
use Francerz\OAuth2\GrantTypes;
use Francerz\OAuth2\AuthCodeInterface;
use Francerz\OAuth2\ClientInterface;
use Francerz\OAuth2\ResourceOwnerInterface;
use Francerz\PowerData\Functions;
use InvalidArgumentException;

class AuthServer
{
    private $findClientHandler;
    private $getResourceOwnerHandler;
    private $createAuthorizationCodeHandler;
    private $findAuthorizationCodeHandler;

    private $client;
    private $resourceOwner;
    private $scopes;

    private $authorizationCode;

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
     * @param callable $handler (ClientInterface $client, ResourceOwnerInterface $owner, string[] scopes) : string
     * @return void
     */
    public function setCreateAuthorizationCodeHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [ClientInterface::class, ResourceOwnerInterface::class, 'array'], 'string')) {
            throw new InvalidArgumentException('Function expected signature is: (ClientInterface $client, ResourceOwnerInterface $owner, string[] scopes) : string');
        }

        $this->createAuthorizationCodeHandler = $handler;
    }

    /**
     * Undocumented function
     *
     * @param callable $handler (string $code) : AuthCodeInterface
     * @return AuthCodeInterface
     */
    public function setFindAuthorizationCodeHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], AuthCodeInterface::class)) {
            throw new InvalidArgumentException('Function expected signature is: (string $code) : AuthCodeInterface');
        }

        $this->findAuthorizationCodeHandler = $handler;
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
                $redirect_uri = new Uri($redirect_uri_str);

                $state = UriHelper::getQueryParam($request->getUri(), 'state');
                $redirect_uri = $redirect_uri->withQueryParams(array(
                    'state' => $state,
                    'error' => 'unsupported_response_type'
                ));

                $response = new Response();
                $response = $response->withStatus(StatusCodes::FOUND);
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
        
        $redirect_uri_str = UriHelper::getQueryParam($request->getUri(), 'redirect_uri');
        $redirect_uri = new Uri($redirect_uri_str);

        $state = UriHelper::getQueryParam($request->getUri(), 'state');
        $redirect_uri = $redirect_uri->withQueryParam('state', $state);

        $scope_str = UriHelper::getQueryParam($request->getUri(), 'scope');
        $this->scopes = explode(' ', $scope_str);

        $cach = $this->createAuthorizationCodeHandler;
        if (!is_callable($cach)) {
            throw new AuthServerException(
                'Callable getAuthorizationCodeHandler not found.'.PHP_EOL.
                'Use '.static::class.'::setGetAuthorizationCodeHandler() to initialize.'
            );
        }

        $this->authorizationCode = $cach($this->client, $this->resourceOwner, $this->scopes);
        $redirect_uri = $redirect_uri->withQueryParam('code', $this->authorizationCode);

        $response = new Response();
        $response = $response->withStatus(StatusCodes::FOUND);
        $response = $response->withHeader('Location', $redirect_uri);

        return $response;
    }

    public function handleTokenRequest(RequestInterface $request) : ResponseInterface
    {
        $params = BodyHelper::getParsedBody($request);

        if (empty($params)) {
            throw new \Exception('No parameters received');
        }

        if (!array_key_exists('grant_type', $params)) {
            throw new \Exception('No grant_type received.');
        }

        switch($params['grant_type']) {
            case GrantTypes::AUTHORIZATION_CODE:
                return $this->handleTokenRequestCode($request);
                break;
        }
    }

    private function handleTokenRequestCode(RequestInterface $request) : ResponseInterface
    {
        $params = BodyHelper::getParsedBody($request);
        if (!array_key_exists('code', $params)) {
            throw new \Exception('Missing code parameter.');
        }
        $code = $params['code'];
        if (!array_key_exists('client_id', $params)) {
            throw new \Exception('Missing client_id parameter.');
        }
        $client_id = $params['client_id'];

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

        if ($this->client->isConfidential()) {
            $auth = MessageHelper::getAuthorizationHeader($request, $authType, $authContent);

            if (array_key_exists('client_secret', $params)) {
                $client_secret = $params['client_secret'];
            } elseif ($authType == 'Basic') {
                $client_secret = $auth['password'];
            } else {
                throw new \Exception('Missing client_secret');
            }

            if ($this->client->getClientSecret() !== $client_secret) {
                throw new \Exception('Incorrect client credentials');
            }
        }

        $fach = $this->findAuthorizationCodeHandler;
        if (!is_callable($fach)) {
            throw new \Exception('Callable findAuthorizationCodeHandler not found');
        }
        $authCode = $fach($code);

        if ($authCode->getClientId() != $client_id) {
            throw new \Exception('Authorization code not matching with client credentials.');
        }
        if ($authCode->isUsed()) {
            throw new \Exception('Authorization code already used.');
        }
        if ($authCode->isExpired()) {
            throw new \Exception('Authorization code expired.');
        }
        $authCode = $authCode->withRedeemTime(time());
        $authCode->save();

        $accessToken = new AccessToken('abc','Bearer', 3600, 'def');

        $response = new Response();
        return $response;
    }
}