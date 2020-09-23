<?php

use Francerz\Http\Response;
use Francerz\OAuth2\Roles\AuthClient;
use Francerz\OAuth2\Flow\AuthorizationCodeRequest;
use Francerz\OAuth2\Roles\AuthServer;
use Francerz\Http\Uri;
use Francerz\Http\ServerRequest;
use Francerz\OAuth2\Client;
use Francerz\OAuth2\ResourceOwner;
use Francerz\OAuth2\ClientInterface;
use Francerz\OAuth2\ResourceOwnerInterface;
use Francerz\OAuth2\Roles\AuthCodeInterface;

// Client side request initiation

$authClient = new AuthClient(
    'my_client_id',
    'AbCdEfGhIjKlMnOpQrStUvWxYz',
    new Uri('https://www.example.com/oauth2/token'),
    new Uri('https://www.example.com/oauth2/auth')
);
$authClient->setCheckStateHandler(function(string $state) : bool {
    return true;
});

$authReq = new AuthorizationCodeRequest($authClient);
$authReq = $authReq
    ->withRedirectUri(new Uri('http://www.my-app.com/oauth2/callback'))
    ->withState('abc123');

$request = $authReq->getRequest();

/**
 * GET /oauth2/auth
 *     ?response_type=code
 *     &client_id=my_client_id
 *     &redirect_uri=http%3A%2F%2Fwww.my-app.com%2Foauth2%2Fcallback
 *     &state=abc123
 *     HTTP/1.1
 * Host: www.example.com
 */

// ////////////////////////////////////
// Server side request reception

$authServer = new AuthServer();
$authServer->setFindClientHandler(function($client_id) : ClientInterface {
    return new Client($client_id);
});
$authServer->setGetResourceOwnerHandler(function() : ResourceOwnerInterface {
    return new ResourceOwner('12345');
});
$authServer->setCreateAuthorizationCodeHandler(function(Client $client, ResourceOwner $ro, array $scopes) : AuthCodeInterface {
    return 'AuthCode_0123456789';
});

$response = $authServer->handleAuthRequest(new ServerRequest());
// Sends response to client.
/**
 * HTTP/1.1 302 FOUND
 * Location: http://www.my-app.com/oauth2/callback
 *     ?state=abc123
 *     &code=AuthCode_0123456789
 */

// ////////////////////////////////////
// Client side Response handling
try {
    $authClient->handleAuthCode(new ServerRequest());
} catch (Exception $ex) {
    throw $ex;
}
