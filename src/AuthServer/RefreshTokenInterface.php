<?php

namespace Francerz\OAuth2\AuthServer;

interface RefreshTokenInterface
{
    public function getRefreshToken() : string;
    public function withRefreshToken(string $refreshToken) : RefreshTokenInterface;

    public function getClientId() : string;
    public function withClientId(string $clientId) : RefreshTokenInterface;

    public function getOwnerId() : string;
    public function withOwnerId(string $ownerId) : RefreshTokenInterface;

    public function getScope() : string;
    public function withScope(string $scope) : RefreshTokenInterface;
}