<?php

namespace Francerz\OAuth2\AuthServer;

use Francerz\Http\Constants\StatusCodes;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\UriHelper;
use Francerz\OAuth2\AuthError;
use Francerz\OAuth2\AuthErrorCodes;
use Francerz\OAuth2\AuthorizeRequestTypes;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use LogicException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use RuntimeException;

class AuthorizeServer
{
    private $httpFactory;

    private $createAuthorizationCodeHandler;
    private $findClientHandler;
    private $getResourceOwnerHandler;

    public function __construct(HttpFactoryManager $httpFactory)
    {
        $this->httpFactory = $httpFactory;
    }

    public function getHttpFactory() : HttpFactoryManager
    {
        return $this->httpFactory;
    }

    #region Callable handlers
    public function setFindClientHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], ClientInterface::class)) {
            throw new InvalidArgumentException(
                'findClientHandler signature MUST be: '.
                '(string $client_id) : ?ClientInterface'
            );
        }
        $this->findClientHandler = $handler;
    }

    public function setGetResourceOwnerHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [], ResourceOwnerInterface::class)) {
            throw new InvalidArgumentException(
                'getResourceOwnerHandler signature MUST be: '.
                '() : ?ResourceOwnerInterface'
            );
        }
        $this->getResourceOwnerHandler = $handler;
    }

    public function setCreateAuthorizationCodeHandler(callable $handler)
    {
        if (!Functions::testSignature(
            $handler,
            [ClientInterface::class, ResourceOwnerInterface::class, 'string', UriInterface::class],
            'string')
        ) {
            throw new InvalidArgumentException(
                'createAuthorizationCodeHandler signature MUST be: '.
                '(ClientInterface $client, ResourceOwnerInterface $owner, string $scope, UriInterface $redirect_uri) : string'
            );
        }
        $this->createAuthorizationCodeHandler = $handler;
    }
    #endregion

    public function handle(RequestInterface $request) : ResponseInterface
    {
        $response_type = UriHelper::getQueryParam($request->getUri(), 'response_type');

        switch($response_type) {
            case AuthorizeRequestTypes::AUTHORIZATION_CODE:
                return $this->handleCodeRequest($request);
            default:
                throw new RuntimeException(AuthErrorCodes::INVALID_REQUEST);
        }
        $uriFactory = $this->httpFactory->getUriFactory();
        $state = UriHelper::getQueryParam($request->getUri(), 'state');
        $redirect_uri = UriHelper::getQueryParam($request->getUri(), 'redirect_uri');
        $redirect_uri = $uriFactory->createUri($redirect_uri);
        
        $error = new AuthError($this->httpFactory, $state, AuthErrorCodes::INVALID_REQUEST);
        return $error->getErrorRedirect($redirect_uri);
    }

    private function handleCodeRequest(RequestInterface $request) : ResponseInterface
    {
        $responseFactory = $this->httpFactory->getResponseFactory();
        $uriFactory = $this->httpFactory->getUriFactory();

        $findClientHandler = $this->findClientHandler;
        if (!is_callable($findClientHandler)) {
            throw new LogicException('Missing findClientHandler.');
        }
        $getResourceOwnerHandler = $this->getResourceOwnerHandler;
        if (!is_callable($getResourceOwnerHandler)) {
            throw new LogicException('Missing getResourceOwnerHandler.');
        }
        $createAuthorizationCodeHandler = $this->createAuthorizationCodeHandler;
        if (!is_callable($createAuthorizationCodeHandler)) {
            throw new LogicException('Missing createAuthorizationCodeHandler.');
        }

        $uriParams = UriHelper::getQueryParams($request->getUri());
        if (!array_key_exists('client_id', $uriParams)) {
            throw new RuntimeException('Missing client_id');
        }
        if (!array_key_exists('redirect_uri', $uriParams)) {
            throw new RuntimeException('Missing redirect_uri.');
        }
        $client_id = $uriParams['client_id'];
        $redirect_uri = $uriFactory->createUri($uriParams['redirect_uri']);
        $scope = isset($uriParams['scope']) ? $uriParams['scope'] : '';
        $state = isset($uriParams['state']) ? $uriParams['state'] : '';

        $client = $findClientHandler($client_id);
        if (!isset($client)) {
            throw new RuntimeException('Client not found with given client_id.');
        }
        $resourceOwner = $getResourceOwnerHandler();
        if (!isset($resourceOwner)) {
            throw new RuntimeException();
        }

        $code = $createAuthorizationCodeHandler(
            $client,
            $resourceOwner,
            $scope,
            $redirect_uri
        );

        $redirect_uri = UriHelper::withQueryParams($redirect_uri, array(
            'state' => $state,
            'code' => $code
        ));

        $response = $responseFactory->createResponse(StatusCodes::REDIRECT_FOUND);
        $response = $response->withHeader('Location', (string)$redirect_uri);
        return $response;
    }
}