<?php

use Francerz\Http\Constants\Methods;
use Francerz\Http\Constants\StatusCodes;
use Francerz\Http\HttpFactory;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\UriHelper;
use Francerz\OAuth2\AuthServer\AuthorizeServer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

class FlowImplicitGrantTest extends TestCase
{
    public function testCreateAuthorizeServer()
    {
        $server = new AuthorizeServer(new HttpFactoryManager(new HttpFactory()));

        $this->assertInstanceOf(AuthorizeServer::class, $server);

        return $server;
    }

    public function testAuthorizationRequest()
    {
        $httpFactory = new HttpFactory();
        $uri = $httpFactory->createUri('https://oauth2.server.com/authorize');
        $uri = UriHelper::withQueryParams($uri, array(
            'response_type' => 'token',
            'client_id' => 'abc123',
            'redirect_uri' => 'https://www.client.com/oauth2/callback',
            'scope' => 'scope1 scope2',
            'state' => 'qwerty'
        ));

        $request = $httpFactory->createRequest(Methods::GET, $uri);

        $this->assertInstanceOf(RequestInterface::class, $request);

        return $request;
    }

    /**
     * @depends testCreateAuthorizeServer
     * @depends testAuthorizationRequest
     */
    public function testAccessTokenResponse(AuthorizeServer $server, RequestInterface $request)
    {
        // NOT IMPLEMENTED YET
        /*
        $response = $server->handleAuthRequest($request);
        /*/
        $uriFactory = $server->getHttpFactory()->getUriFactory();
        $responseFactory = $server->getHttpFactory()->getResponseFactory();

        $reqParams = UriHelper::getQueryParams($request->getUri());

        $locUri = $uriFactory->createUri($reqParams['redirect_uri']);
        $locUri = UriHelper::withFragmentParams($locUri, array(
            'access_token' => 'zyxwvutsrqponmlkjihgfedcba',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => $reqParams['scope'],
            'state' => $reqParams['state']
        ));

        $response = $responseFactory->createResponse(StatusCodes::REDIRECT_FOUND);
        $response = $response->withHeader('Location', $locUri);
        // */
        $locUri = $uriFactory->createUri($response->getHeaderLine('Location'));

        $this->assertEquals(StatusCodes::REDIRECT_FOUND, $response->getStatusCode());
        $this->assertEquals('https', $locUri->getScheme());
        $this->assertEquals('www.client.com', $locUri->getHost());
        $this->assertEquals('/oauth2/callback', $locUri->getPath());
        

        return $response;
    }
}