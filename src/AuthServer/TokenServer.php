<?php

namespace Francerz\OAuth2\AuthServer;

use Francerz\Http\Constants\MediaTypes;
use Francerz\Http\Constants\StatusCodes;
use Francerz\Http\Headers\BasicAuthorizationHeader;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\MessageHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\AuthCodeInterface;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\RefreshTokenInterface;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use Francerz\OAuth2\TokenRequestGrantTypes;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use LogicException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

class TokenServer
{
    private $httpFactory;

    private $createAccessTokenHandler;
    private $findAuthorizationCodeHandler;
    private $findClientHandler;
    private $findRefreshTokenHandler;
    private $findResourceOwnerHandler;
    private $updateAuthorizationCodeRedeemTimeHandler;

    public function __construct(HttpFactoryManager $httpFactory)
    {
        $this->httpFactory = $httpFactory;
    }

    public function getHttpFactory() : HttpFactoryManager
    {
        return $this->httpFactory;
    }

    #region Callable Handlers
    public function setCreateAccessTokenHandler(callable $handler)
    {
        if (!Functions::testSignature(
            $handler,
            [ClientInterface::class, ResourceOwnerInterface::class, 'string'],
            AccessToken::class)
        ) {
            throw new InvalidArgumentException(
                'Handler createAccesToken signature MUST be: '.
                '(ClientInterface $client, ResourceOwnerInterface $owner, string $scope)'
            );
        }
        $this->createAccessTokenHandler = $handler;
    }
    public function setFindAuthorizationCodeHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], AuthCodeInterface::class)) {
            throw new InvalidArgumentException(
                'Handler findAuthorizationCodeHandler signature MUST be: '.
                '(string $code) : AuthCodeInterface'
            );
        }
        $this->findAuthorizationCodeHandler = $handler;
    }
    public function setFindClientHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], ClientInterface::class)) {
            throw new InvalidArgumentException(
                'Handler findClient signature MUST be: '.
                '(string $client_id) : ClientInterface'
            );
        }
        $this->findClientHandler = $handler;
    }
    public function setFindRefreshTokenHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], RefreshTokenInterface::class)) {
            throw new InvalidArgumentException(
                'Handler findRefreshToken signature MUST be: '.
                '(string $refreshToken) : RefreshTokenInterface'
            );
        }
        $this->findRefreshTokenHandler = $handler;
    }
    public function setFindResourceOwnerHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], ResourceOwnerInterface::class)) {
            throw new InvalidArgumentException(
                'Handler findResourceOwner signature MUST be: '.
                '(string $ownerId) : ResourceOwnerInterface'
            );
        }
        $this->findResourceOwnerHandler = $handler;
    }
    public function setUpdateAuthorizationCodeRedeemTimeHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AuthCodeInterface::class])) {
            throw new InvalidArgumentException(
                'Handler updateAuthorizationCodeRedeemTime signature MUST be: '.
                '(AuthCodeInterface $authCode) : void'
            );
        }
        $this->updateAuthorizationCodeRedeemTimeHandler = $handler;
    }
    #endregion


    public function handle(RequestInterface $request): ResponseInterface
    {
        $params = MessageHelper::getContent($request);

        if (empty($params)) {
            throw new RuntimeException('No parameters received.');
        }

        if (!array_key_exists('grant_type', $params)) {
            throw new RuntimeException('No grant_type received.');
        }


        switch ($params['grant_type']) {
            case TokenRequestGrantTypes::AUTHORIZATION_CODE:
                return $this->handleCodeRequest($request);
            case TokenRequestGrantTypes::REFRESH_TOKEN:
                return $this->handleRefreshTokenRequest($request);
        }
    }

    public function handleCodeRequest(RequestInterface $request) : ResponseInterface
    {
        #region Callable checks
        $findResourceOwnerHandler = $this->findResourceOwnerHandler;
        if (!is_callable($findResourceOwnerHandler)) {
            throw new LogicException('Callable findResourceOwnerHandler not found.');
        }

        $createAccessTokenHandler = $this->createAccessTokenHandler;
        if (!is_callable($createAccessTokenHandler)) {
            throw new LogicException('Callable createAccessTokenHandler not found.');
        }
        $findAuthorizationCodeHandler = $this->findAuthorizationCodeHandler;
        if (!is_callable($findAuthorizationCodeHandler)) {
            throw new LogicException('Callable findAuthorizationCodeHandler not found.');
        }

        $updateAuthorizationCodeRedeemTimeHandler = $this->updateAuthorizationCodeRedeemTimeHandler;
        if (!is_callable($updateAuthorizationCodeRedeemTimeHandler)) {
            throw new LogicException('Callable updateAuthorizationCodeRedeemTimeHandler not found.');
        }
        #endregion

        $client = $this->checkClientCredentials($request);

        $params = MessageHelper::getContent($request);

        if (!array_key_exists('code', $params)) {
            throw new RuntimeException('Missing code parameter.');
        }
        $code = $params['code'];
        $authCode = $findAuthorizationCodeHandler($code);

        if ($authCode->getClientId() != $client->getClientId()) {
            throw new RuntimeException('Authorization code not matching with client credentials.');
        }
        if ($authCode->isUsed()) {
            throw new RuntimeException('Authorization code is already used.');
        }
        if ($authCode->isExpired()) {
            throw new RuntimeException('Authorization code expired.');
        }

        $resourceOwner = $findResourceOwnerHandler($authCode->getOwnerId());

        $authCode = $authCode->withRedeemTime(time());
        $updateAuthorizationCodeRedeemTimeHandler($authCode);

        $accessToken = $createAccessTokenHandler(
            $client,
            $resourceOwner,
            $authCode->getScope()
        );

        $response = $this->buildAccessTokenResponse($accessToken);

        return $response;
    }

    public function handleRefreshTokenRequest(RequestInterface $request) : ResponseInterface
    {
        #region Callable checks
        $findResourceOwnerHandler = $this->findResourceOwnerHandler;
        if (!is_callable($findResourceOwnerHandler)) {
            throw new LogicException('Callable findResourceOwnerHandler not found.');
        }

        $createAccessTokenHandler = $this->createAccessTokenHandler;
        if (!is_callable($createAccessTokenHandler)) {
            throw new LogicException('Callable createAccessTokenHandler not found.');
        }

        $findRefreshTokenHandler = $this->findRefreshTokenHandler;
        if (!is_callable($findRefreshTokenHandler)) {
            throw new LogicException('Callable findRefreshTokenHandler not found.');
        }
        #endregion

        $client = $this->checkClientCredentials($request);
        $params = MessageHelper::getContent($request);

        if (!array_key_exists('refresh_token', $params)) {
            throw new RuntimeException('Missing refresh_token.');
        }
        
        $refreshToken = $findRefreshTokenHandler($params['refresh_token']);
        if (!isset($refreshToken)) {
            throw new RuntimeException('Invalid refresh_token.');
        }

        if ($refreshToken->getClientId() !== $client->getClientId()) {
            throw new RuntimeException('Refresh token not matches with client credentials.');
        }

        $resourceOwner = $findResourceOwnerHandler($refreshToken->getOwnerId());
        if (!isset($resourceOwner)) {
            throw new RuntimeException('Unknown Resource Owner.');
        }

        $accessToken = $createAccessTokenHandler($client, $resourceOwner, $refreshToken->getScope());

        return $this->buildAccessTokenResponse($accessToken);
    }

    private function getClientCredentials(
        RequestInterface $request,
        ?string &$client_id = '',
        ?string &$client_secret = ''
    ) {
        $auth = MessageHelper::getFirstAuthorizationHeader($request);

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

    private function checkClientCredentials(RequestInterface $request) : ClientInterface
    {
        $findClientHandler = $this->findClientHandler;
        if (!is_callable($findClientHandler)) {
            throw new LogicException('findClientHandler not found.');
        }

        $this->getClientCredentials($request, $client_id, $client_secret);

        if (empty($client_id)) {
            throw new RuntimeException('Missing client_id.');
        }

        $client = $findClientHandler($client_id);
        if (!isset($client)) {
            throw new RuntimeException('Unknown client_id.');
        }

        if ($client->isConfidential()) {
            if (empty($client_secret)) {
                throw new RuntimeException('Missing client_secret.');
            }
            if ($client->getClientSecret() !== $client_secret) {
                throw new RuntimeException('Incorrect client credentials.');
            }
        }

        return $client;
    }

    private function buildAccessTokenResponse(AccessToken $accessToken) : ResponseInterface
    {
        $responseFactory = $this->httpFactory->getResponseFactory();
        $response = $responseFactory->createResponse(StatusCodes::SUCCESS_OK)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
        $response = MessageHelper::withContent(
            $response,
            MediaTypes::APPLICATION_JSON,
            $accessToken
        );

        return $response;
    }
}