<?php

namespace Francerz\OAuth2\AuthServer;

interface ClientInterface
{
    public function getClientId() : string;
    public function getClientSecret() : string;
    public function isConfidential() : bool;
    public function withParam(string $name, $value) : ClientInterface;
    public function getParam(string $name);
}