<?php

namespace Francerz\OAuth2\AuthServer;

use Francerz\OAuth2\ResourceOwnerInterface;

class ResourceOwner implements ResourceOwnerInterface
{
    private $uniqueId;
    public function __construct(string $uniqueId)
    {
        $this->uniqueId = $uniqueId;
    }

    public function getUniqueId(): string
    {
        return $this->uniqueId;
    }
}