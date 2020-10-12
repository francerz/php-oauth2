<?php

namespace Francerz\OAuth2;

use Francerz\Http\Response;
use Francerz\OAuth2\Exceptions\HandleableExceptionInterface;
use Psr\Http\Message\ResponseInterface;

class AuthExceptionHandler
{
    public static function handleServerAuthException(HandleableExceptionInterface $ex) : ResponseInterface
    {
        return new Response();
    }

    public static function handleClientAuthException(HandleableExceptionInterface $ex) : ResponseInterface
    {
        return new Response();
    }

    public static function handleServerTokenException(HandleableExceptionInterface $ex) : ResponseInterface
    {
        return new Response();
    }

    public static function handleClientTokenException(HandleableExceptionInterface $ex) : ResponseInterface
    {
        return new Response();
    }
}