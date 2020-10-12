<?php

use Francerz\Http\Helpers\UriHelper;
use Francerz\Http\Methods;
use Francerz\Http\Request;
use Francerz\Http\Response;
use Francerz\Http\StatusCodes;
use Francerz\Http\Uri;
use Francerz\OAuth2\Roles\AuthServer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

class FlowImplicitGrantTest extends TestCase
{
    public function testCreateServer()
    {
        $server = new AuthServer();

        $this->assertInstanceOf(AuthServer::class, $server);

        return $server;
    }

    public function testAuthorizationRequest()
    {
        $uri = new Uri('https://oauth2.server.com/authorize');
        $uri = UriHelper::withQueryParams($uri, array(
            'response_type' => 'token',
            'client_id' => 'abc123',
            'redirect_uri' => 'https://www.client.com/oauth2/callback',
            'scope' => 'scope1 scope2',
            'state' => 'qwerty'
        ));

        $request = new Request($uri, Methods::GET);

        $this->assertInstanceOf(RequestInterface::class, $request);

        return $request;
    }

    /**
     * @depends testCreateServer
     * @depends testAuthorizationRequest
     *
     * @param AuthServer $server
     * @param RequestInterface $request
     * @return void
     */
    public function testAccessTokenResponse(AuthServer $server, RequestInterface $request)
    {
        // NOT IMPLEMENTED YET
        /*
        $response = $server->handleAuthRequest($request);
        /*/
        $reqParams = UriHelper::getQueryParams($request->getUri());

        $locUri = new Uri($reqParams['redirect_uri']);
        $locUri = UriHelper::withFragmentParams($locUri, array(
            'access_token' => 'zyxwvutsrqponmlkjihgfedcba',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => $reqParams['scope'],
            'state' => $reqParams['state']
        ));

        $response = new Response();
        $response = $response
            ->withStatus(StatusCodes::FOUND)
            ->withHeader('Location', $locUri);
        // */
        $locUri = new Uri($response->getHeaderLine('Location'));

        $this->assertEquals(StatusCodes::FOUND, $response->getStatusCode());
        $this->assertEquals('https', $locUri->getScheme());
        $this->assertEquals('www.client.com', $locUri->getHost());
        $this->assertEquals('/oauth2/callback', $locUri->getPath());
        

        return $response;
    }
}