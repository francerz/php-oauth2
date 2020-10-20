<?php

use Francerz\Http\Constants\Methods;
use Francerz\Http\HttpFactory;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\MessageHelper;
use Francerz\Http\Tools\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthServer\AuthCode;
use Francerz\OAuth2\AuthServer\AuthCodeInterface;
use Francerz\OAuth2\AuthServer\AuthorizeServer;
use Francerz\OAuth2\AuthServer\Client;
use Francerz\OAuth2\AuthServer\ClientInterface;
use Francerz\OAuth2\AuthServer\ResourceOwner;
use Francerz\OAuth2\AuthServer\ResourceOwnerInterface;
use Francerz\OAuth2\AuthServer\TokenServer;
use Francerz\OAuth2\Client\AuthClient;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class FlowAuthCodeTest extends TestCase
{
    public function testCreateAuthorizeServer() : AuthorizeServer
    {
        $authHandler = new AuthorizeServer(new HttpFactoryManager(new HttpFactory()));

        $authHandler->setFindClientHandler(function(string $client_id) : ?ClientInterface {
            return new Client($client_id);
        });
        $authHandler->setGetResourceOwnerHandler(function() : ?ResourceOwnerInterface {
            return new ResourceOwner(12345);
        });
        $authHandler->setCreateAuthorizationCodeHandler(function(ClientInterface $client, ResourceOwnerInterface $owner, string $scope, UriInterface $redirectUri) : string {
            return 'abcdefghijklmnopqrstuvwxyz';
        });

        $this->assertInstanceOf(AuthorizeServer::class, $authHandler);

        return $authHandler;
    }

    public function testCreateTokenServer() : TokenServer
    {
        $tokenServer = new TokenServer(new HttpFactoryManager(new HttpFactory()));

        $tokenServer->setFindClientHandler(function(string $client_id) : ClientInterface {
            return new Client($client_id);
        });
        $tokenServer->setFindResourceOwnerHandler(function(string $ownerUniqueId) : ResourceOwnerInterface {
            return new ResourceOwner($ownerUniqueId);
        });
        
        $tokenServer->setFindAuthorizationCodeHandler(function(string $code) use ($tokenServer) : AuthCodeInterface {
            $uriFactory = $tokenServer->getHttpFactory()->getUriFactory();
            return new AuthCode(
                '1234567890abcdef',
                12345,
                $code,
                'scope1 scope2',
                $uriFactory->createUri('https://www.client.com/oauth2/callback')
            );
        });
        $tokenServer->setUpdateAuthorizationCodeRedeemTimeHandler(function(AuthCodeInterface $authCode) {

        });
        $tokenServer->setCreateAccessTokenHandler(function(
            ClientInterface $client,
            ResourceOwnerInterface $owner,
            string $scope
        ) : AccessToken {
            return new AccessToken(
                'zyxwvutsrqponmlkjihgfedcba',
                'Bearer',
                3600,
                'AbCdEfGhIjKlMnOpQrStUvWxYz'
            );
        });

        $this->assertInstanceOf(TokenServer::class, $tokenServer);

        return $tokenServer;
    }
    public function testCreateClient() : AuthClient
    {
        $client = new AuthClient(
            new HttpFactoryManager(new HttpFactory()),
            '1234567890abcdef',
            '',
           'https://oauth2.server.com/token',
           'https://oauth2.server.com/request',
           'https://www.client.com/oauth2/callback'
        );
        $client->setCheckStateHandler(function(string $state): bool {
            return $state === 'qwerty';
        });

        $this->assertInstanceOf(AuthClient::class, $client);
        return $client;
    }

    /**
     * @depends testCreateClient
     *
     * @return void
     */
    public function testGetAuthorizationCodeRequestUri(AuthClient $client) : UriInterface
    {
        $reqUri = $client->getAuthorizationCodeRequestUri(['scope1', 'scope2'], 'qwerty');

        $this->assertEquals('https', $reqUri->getScheme());
        $this->assertEquals('oauth2.server.com', $reqUri->getHost());
        $this->assertEquals('/request', $reqUri->getPath());

        $reqUriParams = UriHelper::getQueryParams($reqUri);
        $this->assertEquals('qwerty', $reqUriParams['state']);
        $this->assertEquals('code', $reqUriParams['response_type']);
        $this->assertEquals('scope1 scope2', $reqUriParams['scope']);
        $this->assertEquals('1234567890abcdef', $reqUriParams['client_id']);
        $this->assertEquals('https://www.client.com/oauth2/callback', $reqUriParams['redirect_uri']);

        return $reqUri;
    }

    /**
     * @depends testCreateAuthorizeServer
     * @depends testGetAuthorizationCodeRequestUri
     *
     * @return void
     */
    public function testHandleAuthCodeRequest(AuthorizeServer $authHandler, UriInterface $uri)
    {
        $uriFactory = $authHandler->getHttpFactory()->getUriFactory();
        $requestFactory = $authHandler->getHttpFactory()->getRequestFactory();

        // Creates resquest from uri just like a browser would do.
        $request = $requestFactory->createRequest(Methods::GET, $uri);

        // Starts the real test.
        $response = $authHandler->handle($request);

        $location = $response->getHeaderLine('Location');
        $locUri = $uriFactory->createUri($location);

        $this->assertEquals('https', $locUri->getScheme());
        $this->assertEquals('www.client.com', $locUri->getHost());
        $this->assertEquals('/oauth2/callback', $locUri->getPath());

        $locUriParams = UriHelper::getQueryParams($locUri);
        $this->assertEquals('qwerty', $locUriParams['state']);
        $this->assertEquals('abcdefghijklmnopqrstuvwxyz', $locUriParams['code']);

        return $response;
    }

    /**
     * @depends testCreateClient
     * @depends testHandleAuthCodeRequest
     */
    public function testHandleAuthCodeResponse(AuthClient $client, ResponseInterface $response)
    {
        $uriFactory = $client->getHttpFactory()->getUriFactory();
        $requestFactory = $client->getHttpFactory()->getRequestFactory();

        // Creates request from redirection just like a browser would do.
        $location = $response->getHeaderLine('Location');
        $locUri = $uriFactory->createUri($location);
        $request = $requestFactory->createRequest(Methods::GET, $locUri);

        // Starts the real test.
        $redeemAuthCodeRequest = $client->getRedeemAuthCodeRequest($request);

        $tokenUri = $redeemAuthCodeRequest->getUri();
        $this->assertEquals('https', $tokenUri->getScheme());
        $this->assertEquals('oauth2.server.com', $tokenUri->getHost());
        $this->assertEquals('/token', $tokenUri->getPath());

        $body = MessageHelper::getContent($redeemAuthCodeRequest);

        $this->assertEquals('authorization_code', $body['grant_type']);
        $this->assertEquals('abcdefghijklmnopqrstuvwxyz', $body['code']);
        $this->assertEquals('https://www.client.com/oauth2/callback', $body['redirect_uri']);

        if (empty($redeemAuthCodeRequest->getHeader('Authorization'))) {
            $this->assertEquals('1234567890abcdef', $body['client_id']);
            $this->assertEquals('', $body['client_secret']);
        }

        return $redeemAuthCodeRequest;
    }

    /**
     * @depends testCreateTokenServer
     * @depends testHandleAuthCodeResponse
     * @return void
     */
    public function testHandleRedeemAuthCodeRequest(TokenServer $tokenHandler, RequestInterface $request) : ResponseInterface
    {
        $response = $tokenHandler->handle($request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-store', $response->getHeaderLine('Cache-Control'));
        $this->assertEquals('no-cache', $response->getHeaderLine('Pragma'));

        return $response;
    }

    /**
     * @depends testCreateClient
     * @depends testHandleRedeemAuthCodeRequest
     *
     * @param AuthClient $client
     * @param ResponseInterface $response
     * @return void
     */
    public function testHandleAccessTokenResponse(AuthClient $client, ResponseInterface $response)
    {
        $accessToken = $client->getAccessTokenFromResponse($response);

        $this->assertEquals('zyxwvutsrqponmlkjihgfedcba', $accessToken->getAccessToken());
        $this->assertEquals('Bearer', $accessToken->getTokenType());
        $this->assertEquals(3600, $accessToken->getExpiresIn());
        $this->assertEquals('AbCdEfGhIjKlMnOpQrStUvWxYz', $accessToken->getRefreshToken());
    }
}