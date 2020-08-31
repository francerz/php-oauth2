<?php

namespace Francerz\OAuth2;

use Francerz\Http\Helpers\BodyHelper;
use Francerz\Http\Helpers\MessageHelper;
use Francerz\Http\Helpers\UriHelper;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Francerz\Http\Uri;
use Francerz\Http\Response;
use Francerz\Http\StatusCodes;
use Francerz\OAuth2\Exceptions\AuthServerException;
use Francerz\OAuth2\Exceptions\InvalidRequestException;
use Francerz\OAuth2\Exceptions\UnavailableResourceOwnerException;
use Francerz\OAuth2\Roles\AuthCodeInterface;
use Francerz\OAuth2\Roles\ClientInterface;
use Francerz\OAuth2\Roles\ResourceOwnerInterface;
use InvalidArgumentException;
use ReflectionFunction;

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
        $rf = new ReflectionFunction($handler);

        // check if handler returns ClientInterface object.
        $retType = $rf->getReturnType();
        if (!is_subclass_of($retType->getName(), ClientInterface::class)) {
            throw new InvalidArgumentException('Function return type must be \''.ClientInterface::class.'\'.');
        }

        // check if handler has $client_id:string parameter.
        $args = $rf->getParameters();
        if (count($args) < 1 || $args[0]->getType()->getName() !== 'string') {
            throw new InvalidArgumentException('Function must contain one parameter type string for $client_id');
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
        $rf = new ReflectionFunction($handler);

        $retType = $rf->getReturnType();
        if (!is_subclass_of($retType->getName(), ResourceOwnerInterface::class)) {
            throw new InvalidArgumentException('Function return type must be \''.ResourceOwnerInterface::class.'\'.');
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
        $rf = new ReflectionFunction($handler);

        $rt = $rf->getReturnType();
        if ($rt->getName() !== 'string') {
            throw new InvalidArgumentException('Function return type must be \'string\'.');
        }

        // check handler has expected parameters.
        $args = $rf->getParameters();
        if (count($args) < 3
            || !is_subclass_of($args[0]->getName(), ClientInterface::class)
            || !is_subclass_of($args[1]->getName(), ResourceOwnerInterface::class)
            || $args[2]->getName() !== 'array'
        ) {
            throw new InvalidArgumentException(
                'Function parameters must be (ClientInterface, ResourceOwnerInterface, array $scopes)'
            );
        }

        $this->createAuthorizationCodeHandler = $handler;
    }

    public function setFindAuthorizationCodeHandler(callable $handler)
    {
        $rf = new ReflectionFunction($handler);

        $rt = $rf->getReturnType();
        if (!is_subclass_of($rt->getName(), AuthCodeInterface::class)) {
            throw new InvalidArgumentException('Function must return an '.AuthCodeInterface::class.' object.');
        }

        $args = $rf->getParameters();
        if (count($args) < 1 || $args[0]->getType()->getName() != 'string') {
            throw new InvalidArgumentException('Function must have one parameter type string for code.');
        }

        $this->findAuthorizationCodeHandler = $handler;
    }
    #endregion

    public function handleAuthRequest(RequestInterface $request)
    {
        $request_type = UriHelper::getQueryParam($request->getUri(), 'request_type');

        switch($request_type) {
            case 'code':
                return $this->handleAuthRequestCode($request);
                break;
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
        
        $redirect_uri_str = UriHelper::getQueryParam($request->getUri(), 'redirect_uri');;
        $redirect_uri = new Uri($redirect_uri_str);

        $state = UriHelper::getQueryParam($request->getUri(), 'state');;
        $redirect_uri = $redirect_uri->withQueryParam('state', $state);

        $scope_str = UriHelper::getQueryParam($request->getUri(), 'scope');;
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

    public function handleTokenRequest(RequestInterface $request)
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
            throw new \Exception('Missing client_id_ parameter.');
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