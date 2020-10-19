<?php

namespace Francerz\OAuth2\AuthServer;

class RefreshToken implements RefreshTokenInterface
{
    private $refreshToken;
    private $clientId;
    private $ownerId;
    private $scope;

    public function __construct(string $refreshToken, string $clientId, string $ownerId, string $scope = '')
    {
        $this->refreshToken = $refreshToken;
        $this->clientId = $clientId;
        $this->ownerId = $ownerId;
        $this->scope = $scope;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function withRefreshToken(string $refreshToken): RefreshToken
    {
        $new = clone $this;
        $new->refreshToken = $refreshToken;
        return $new;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function withClientId(string $clientId): RefreshToken
    {
        $new = clone $this;
        $new->clientId = $clientId;
        return $new;
    }

    public function getOwnerId(): string
    {
        return $this->ownerId;
    }

    public function withOwnerId(string $ownerId): RefreshToken
    {
        $new = clone $this;
        $new->ownerId = $ownerId;
        return $new;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function withScope(string $scope): RefreshToken
    {
        $new = clone $this;
        $new->scope = $scope;
        return $new;
    }
}