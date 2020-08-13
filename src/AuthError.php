<?php

namespace Francerz\OAuth2;

use Psr\Http\Message\UriInterface;

class AuthError
{
    private string $error;
    private string $errorDescription;
    private UriInterface $errorUri;
    private string $state;
}