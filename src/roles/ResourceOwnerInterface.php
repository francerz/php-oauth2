<?php

namespace Francerz\OAuth2\Roles;

interface ResourceOwnerInterface
{
    public function getUniqueId() : string;
}