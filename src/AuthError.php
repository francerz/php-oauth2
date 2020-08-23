<?php

namespace Francerz\OAuth2;

use Psr\Http\Message\UriInterface;

class AuthError
{
    private $error; // string
    private $errorDescription; // error
    private $errorUri; // UriInterface
    private $state; // string
}