<?php

use Francerz\Http\BodyParsers;
use Francerz\Http\Helpers\MessageHelper;
use Francerz\Http\Helpers\UriHelper;
use Francerz\Http\Parsers\UrlEncodedParser;
use Francerz\Http\Request;
use Francerz\Http\Uri;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthCode;
use Francerz\OAuth2\AuthCodeInterface;
use Francerz\OAuth2\Client;
use Francerz\OAuth2\ClientInterface;
use Francerz\OAuth2\Flow\AuthorizationCodeRequest;
use Francerz\OAuth2\ResourceOwner;
use Francerz\OAuth2\ResourceOwnerInterface;
use Francerz\OAuth2\Roles\AuthClient;
use Francerz\OAuth2\Roles\AuthServer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class FlowAuthCodeTest extends TestCase
{
    public function testCreateServer() : AuthServer
    {
        $server = new AuthServer();
        $server->setFindClientHandler(function(string $client_id) : ClientInterface {
            return new Client($client_id);
        });
        $server->setGetResourceOwnerHandler(function() : ResourceOwnerInterface {
            return new ResourceOwner(12345);
        });
        $server->setFindResourceOwnerHandler(function(string $ownerUniqueId) : ResourceOwnerInterface {
            return new ResourceOwner($ownerUniqueId);
        });
        $server->setCreateAuthorizationCodeHandler(function(ClientInterface $client, ResourceOwnerInterface $owner, string $scope, UriInterface $redirectUri) : string {
            return 'abcdefghijklmnopqrstuvwxyz';
        });
        $server->setFindAuthorizationCodeHandler(function(string $code) : AuthCodeInterface {
            return new AuthCode(
                '1234567890abcdef',
                12345,
                $code,
                'scope1 scope2',
                new Uri('https://www.client.com/oauth2/callback')
            );
        });
        $server->setUpdateAuthorizationCodeRedeemTimeHandler(function(AuthCodeInterface $authCode) {

        });
        $server->setCreateAccessTokenHandler(function(
            ClientInterface $client,
            ResourceOwnerInterface $owner,
            string $scope
        ) : AccessToken {
            return new AccessToken('zyxwvutsrqponmlkjihgfedcba', 'Bearer', 3600, 'AbCdEfGhIjKlMnOpQrStUvWxYz');
        });

        $this->assertInstanceOf(AuthServer::class, $server);
        return $server;
    }
    public function testCreateClient() : AuthClient
    {
        $client = new AuthClient(
            '1234567890abcdef',
            null,
            new Uri('https://oauth2.server.com/token'),
            new Uri('https://oauth2.server.com/request'),
            new Uri('https://www.client.com/oauth2/callback')
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
        $codeReq = new AuthorizationCodeRequest($client);
        $codeReq = $codeReq
            ->withState('qwerty')
            ->withAddedScope(['scope1', 'scope2']);
        $reqUri = $codeReq->getRequestUri();

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
     * @depends testCreateServer
     * @depends testGetAuthorizationCodeRequestUri
     *
     * @return void
     */
    public function testHandleAuthCodeRequest(AuthServer $server, UriInterface $uri)
    {
        $request = new Request($uri);

        $response = $server->handleAuthRequest($request);

        $location = $response->getHeaderLine('Location');
        $locUri = new Uri($location);

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
        $location = $response->getHeaderLine('Location');
        $locUri = new Uri($location);

        $request = new Request($locUri);
        $redeemAuthCodeRequest = $client->getRedeemAuthCodeRequest($request);

        $tokenUri = $redeemAuthCodeRequest->getUri();

        $this->assertEquals('https', $tokenUri->getScheme());
        $this->assertEquals('oauth2.server.com', $tokenUri->getHost());
        $this->assertEquals('/token', $tokenUri->getPath());

        BodyParsers::register(UrlEncodedParser::class);
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
     * @depends testCreateServer
     * @depends testHandleAuthCodeResponse
     *
     * @param AuthServer $server
     * @param RequestInterface $request
     * @return void
     */
    public function testHandleRedeemAuthCodeRequest(AuthServer $server, RequestInterface $request) : ResponseInterface
    {
        $response = $server->handleTokenRequest($request);

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