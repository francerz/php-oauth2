<?php

use Francerz\OAuth2\AccessToken;
use PHPUnit\Framework\TestCase;

class AccessTokenTest extends TestCase
{
    public function testInstantiation()
    {
        $at = new AccessToken('abcdefgh', 'Bearer', 3600);

        $this->assertEquals('abcdefgh', $at->access_token);
        $this->assertEquals('Bearer', $at->token_type);
        $this->assertEquals(3600, $at->expires_in);
    }
}