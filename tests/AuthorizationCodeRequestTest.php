<?php

use Francerz\Http\Uri;
use Francerz\OAuth2\Roles\AuthClient;
use Francerz\OAuth2\Flow\AuthorizationCodeRequest;
use PHPUnit\Framework\TestCase;

class AuthorizationCodeRequestTest extends TestCase
{
    public function testGetRequestUri()
    {
        $authClient = new AuthClient(
            'abcdefg',// client_id
            'qwertyuiop', // client_secret
            new Uri('https://example.com/oauth2/token'),
            new Uri('https://example.com/oauth2/auth')
        );

        $authReq = new AuthorizationCodeRequest($authClient);
        $req = $authReq->getRequest();

        $this->assertEquals(
            'https://example.com/oauth2/auth?response_type=code&client_id=abcdefg',
            (string)$req->getUri()
        );
    }
}