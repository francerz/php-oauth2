<?php

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
}
class ResourceOwner implements ResourceOwnerInterface
{

}
#endregion

// Client side request initiation

$authClient = new AuthClient();
$authClient->setClientId('my_client_id');
$authClient->setClientSecret('AbCdEfGhIjKlMnOpQrStUvWxYz');
$authClient->setAuthorizationEndpoint(new Uri('https://www.example.com/oauth2/auth'));

$authReq = new AuthorizationCodeRequest();
$authReq->setAuthClient($authClient);
$authReq->setRedirectUri(new Uri('http://www.my-app.com/oauth2/callback'));
$authReq->setState('abc123');

$uri = $authReq->getRequestUri();

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