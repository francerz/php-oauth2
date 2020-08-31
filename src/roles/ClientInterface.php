<?php

namespace Francerz\OAuth2\Roles;

interface ClientInterface
{
    public function getClientId() : string;
    public function getClientSecret() : string;
    public function isConfidential() : bool;
}