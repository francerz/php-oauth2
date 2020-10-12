<?php

use Francerz\Http\Helpers\MessageHelper;
use Francerz\Http\Uri;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\Client;
use Francerz\OAuth2\ClientInterface;
use Francerz\OAuth2\RefreshToken;
use Francerz\OAuth2\RefreshTokenInterface;
use Francerz\OAuth2\ResourceOwner;
use Francerz\OAuth2\ResourceOwnerInterface;
use Francerz\OAuth2\Roles\AuthClient;
use Francerz\OAuth2\Roles\AuthServer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class FlowRefreshingAccessTokenTest extends TestCase
{
    public function testCreateServer()
    {
        $server = new AuthServer();
        $server->setFindClientHandler(function(string $client_id): ClientInterface {
            return new Client($client_id, 'abcdefghij0123456789', true);
        });
        $server->setFindRefreshTokenHandler(function(string $refreshToken) : RefreshTokenInterface {
            return new RefreshToken($refreshToken, 'abcd1234', '1234', 'scope1 scope2');
        });
        $server->setFindResourceOwnerHandler(function(string $ownerId) : ResourceOwnerInterface {
            return new ResourceOwner($ownerId);
        });
        $server->setCreateAccessTokenHandler(function(ClientInterface $client, ResourceOwner $owner, string $scope) : AccessToken {
            return new AccessToken('0123456789abcdef', 'Bearer', 3600, 'fedcba9876543210');
        });

        $this->assertInstanceOf(AuthServer::class, $server);

        return $server;
    }

    public function testCreateClient()
    {
        $client = new AuthClient(
            'abcd1234',
            'abcdefghij0123456789',
            new Uri('https://oauth2.server.com/token'),
            new Uri('https://oauth2.server.com/authorize'),
            new Uri('https://www.client.com/oauth2/callback')
        );
        $client = $client->withAccessToken(new AccessToken(
            'zyxwvutsrqponmlkjihgfedcba',
            'Bearer',
            3600,
            'AbCdEfGhIj'
        ));

        $this->assertInstanceOf(AuthClient::class, $client);

        return $client;
    }

    /**
     * @depends testCreateClient
     */
    public function testClientGetFetchAccessTokenWithRefreshTokenRequest(AuthClient $client)
    {
        $client->preferBodyAuthentication(false);
        $request = $client->getFetchAccessTokenWithRefreshTokenRequest(
            $client->getAccessToken()->getRefreshToken()
        );

        $params = MessageHelper::getContent($request);

        $this->assertEquals('refresh_token', $params['grant_type']);
        $this->assertEquals('AbCdEfGhIj', $params['refresh_token']);

        $auth = MessageHelper::getAuthorizationHeader($request, $authType, $authContent);
        if ($authType === 'Basic') {
            $this->assertEquals('abcd1234', $auth['user']);
            $this->assertEquals('abcdefghij0123456789', $auth['password']);
        }

        return $request;
    }

    /**
     * @depends testCreateServer
     * @depends testClientGetFetchAccessTokenWithRefreshTokenRequest
     *
     * @param AuthServer $server
     * @param RequestInterface $request
     * @return void
     */
    public function testServerHandleTokenRequest(AuthServer $server, RequestInterface $request)
    {
        $response = $server->handleTokenRequest($request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-store', $response->getHeaderLine('Cache-Control'));
        $this->assertEquals('no-cache', $response->getHeaderLine('Pragma'));
        
        return $response;
    }
    
    /**
     * @depends testCreateClient
     * @depends testServerHandleTokenRequest
     *
     * @param AuthClient $client
     * @param ResponseInterface $response
     * @return void
     */
    public function testHandleAccessTokenResponse(AuthClient $client, ResponseInterface $response)
    {
        $accessToken = $client->getAccessTokenFromResponse($response);

        $this->assertEquals('0123456789abcdef', $accessToken->getAccessToken());
        $this->assertEquals('Bearer', $accessToken->getTokenType());
        $this->assertEquals(3600, $accessToken->getExpiresIn());
        $this->assertEquals('fedcba9876543210', $accessToken->getRefreshToken());
    }
}