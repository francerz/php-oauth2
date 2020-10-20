<?php

use Francerz\Http\HttpFactory;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\UriHelper;
use Francerz\OAuth2\Client\AuthClient;
use PHPUnit\Framework\TestCase;

class AuthorizationCodeRequestTest extends TestCase
{
    public function testGetRequestUri()
    {
        $httpFactory = new HttpFactory();
        $authClient = new AuthClient(
            new HttpFactoryManager($httpFactory),
            'abcdefg',// client_id
            'qwertyuiop', // client_secret
            'https://server.com/oauth2/token',
            'https://server.com/oauth2/authorize',
            'https://client.com/oauth2/callback'
        );

        $authUri = $authClient->getAuthorizationCodeRequestUri(['scp1','scp2'], 'abcdef');

        $this->assertEquals('https', $authUri->getScheme());
        $this->assertEquals('server.com', $authUri->getHost());
        $this->assertEquals('/oauth2/authorize', $authUri->getPath());

        $query = UriHelper::getQueryParams($authUri);
        $this->assertEquals('abcdefg',$query['client_id']);
        $this->assertEquals('scp1 scp2', $query['scope']);
        $this->assertEquals('abcdef', $query['state']);
        $this->assertEquals('code', $query['response_type']);

    }
}