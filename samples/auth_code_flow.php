<?php

use Francerz\Http\Response;
use Francerz\OAuth2\AuthClient;
use Francerz\OAuth2\AuthorizationCodeRequest;
use Francerz\OAuth2\AuthServer;
use Francerz\Http\Uri;
use Francerz\Http\ServerRequest;
use Francerz\OAuth2\Roles\ClientInterface;
use Francerz\OAuth2\Roles\ResourceOwnerInterface;

#region Extra definitions
class Client implements ClientInterface
{
    private string $client_id;

    public function __construct(string $client_id)
    {
        $this->client_id = $client_id;
    }
    public function getClientId() : string
    {
        return $this->client_id;
    }
    public function getClientSecret() : string
    {
        return $this->client_secret;
    }
    public function isConfidential(): bool
    {
        return true;
    }
}
class ResourceOwner implements ResourceOwnerInterface
{

}
#endregion

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

$uri = $authReq->getRequestUri();

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
$authServer->setGetResourceOwnerHandler(function() {
    return new ResourceOwner();
});
$authServer->setGetAuthorizationCodeHandler(function(Client $client, ResourceOwner $ro, array $scopes) : string {
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
