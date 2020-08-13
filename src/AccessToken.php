<?php

namespace Francerz\OAuth2;

class AccessToken implements \JsonSerializable
{

    public string $accessToken;
    public string $tokenType;
    public int $expiresIn;
    public ?string $refreshToken;

    private array $parameters = array();

    private int $createTime;

    public function __construct(
        string $accessToken,
        string $tokenType = 'Bearer',
        int $expiresIn = 3600,
        ?string $refreshToken = null,
        ?int $createTime = null
    ) {
        $this->accessToken = $accessToken;
        $this->tokenType = $tokenType;
        $this->expiresIn = $expiresIn;
        $this->refreshToken = $refreshToken;
        $this->createTime = is_null($createTime) ? time() : $createTime;
    }

    public function jsonSerialize()
    {
        $json = array(
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn
        );
        if (isset($this->refreshToken)) {
            $json['refresh_token'] = $this->refreshToken;
        }
        $json = array_merge($this->parameters, $json);
        return $json;
    }

    public function getExpireTime() : int
    {
        return $this->createTime + $this->expiresIn;
    }

    public function isExpired(int $s = 30) : bool
    {
        return ($this->getExpireTime() >= time() - $s);
    }

    #region Property Accesors
    public function getAccessToken() : string
    {
        return $this->accessToken;
    }
    public function setAccessToken(string $accessToken)
    {
        $this->accessToken = $accessToken;
    }
    public function getTokenType() : string
    {
        return $this->tokenType;
    }
    public function setTokenType(string $tokenType)
    {
        $this->tokenType = $tokenType;
    }
    public function getExpiresIn() : int
    {
        return $this->expiresIn;
    }
    public function setExpiresIn(int $expiresIn)
    {
        $this->expiresIn = $expiresIn;
    }
    public function getRefreshToken() : ?string
    {
        return $this->refreshToken;
    }
    public function setRefreshToken(string $refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }
    #endregion
}