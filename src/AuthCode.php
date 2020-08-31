<?php

namespace Francerz\OAuth2;

use Francerz\OAuth2\Roles\AuthCodeInterface;

class AuthCode implements AuthCodeInterface
{
    private $clientId;
    private $ownerId;
    private $code;
    private $scope;
    private $lifetime;
    private $createTime;
    private $redeemTime;

    public function withClientId(string $client_id): AuthCodeInterface
    {
        $new = clone $this;
        $new->clientId = $client_id;
        return $new;
    }
    
    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function withOwnerId(string $owner_id): AuthCodeInterface
    {
        $new = clone $this;
        $new->ownerId = $owner_id;
        return $new;
    }

    public function getOwnerId(): string
    {
        return $this->ownerId;
    }

    public function withCode(string $code): AuthCodeInterface
    {
        $new = clone $this;
        $new->code = $code;
        return $new;
    }
    
    public function getCode(): string
    {
        return $this->code;
    }

    public function withScope(string $scope): AuthCodeInterface
    {
        $new = clone $this;
        $new->scope = $scope;
        return $new;
    }

    public function getScope() : string
    {
        return $this->scope;
    }

    public function withLifetime(int $lifetime): AuthCodeInterface
    {
        $new = clone $this;
        $new->lifetime = $lifetime;
        return $new;
    }

    public function getLifetime(): int
    {
        return $this->lifetime;
    }

    public function withRedeemTime(int $epoch): AuthCodeInterface
    {
        $new = clone $this;
        $new->redeemTime = $epoch;
        return $new;
    }

    public function getRedeemTime(): int
    {
        return $this->redeemTime;
    }

    public function getExpireTime(): int
    {
        return $this->createTime + $this->lifetime;
    }

    public function isUsed(): bool
    {
        return !empty($this->redeemTime);
    }

    public function isExpiredAt(int $epoch): bool
    {
        return $this->getExpireTime() > $epoch;
    }

    public function isExpired(int $s = 5): bool
    {
        return $this->getExpireTime() > time() - $s;
    }

    public function save()
    {

    }
}