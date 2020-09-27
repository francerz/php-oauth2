<?php

namespace Francerz\OAuth2;

interface AuthCodeInterface
{
    public function withClientId(string $client_id) : AuthCodeInterface;
    public function getClientId() : string;
    
    public function withOwnerId(string $owner_id) : AuthCodeInterface;
    public function getOwnerId() : string;

    public function withCode(string $code) : AuthCodeInterface;
    public function getCode() : string;

    public function withScope(string $scope) : AuthCodeInterface;
    public function getScope() : string;

    public function withLifetime(int $lifetime) : AuthCodeInterface;
    public function getLifetime() : int;

    public function withRedeemTime(int $epoch) : AuthCodeInterface;
    public function getRedeemTime() : int;

    public function getExpireTime() : int;
    public function isUsed() : bool;
    public function isExpiredAt(int $epoch) : bool;
    public function isExpired(int $s = 5) : bool;

    public function withParam(string $name, $value) : AuthCodeInterface;
    public function getParam(string $name);
}