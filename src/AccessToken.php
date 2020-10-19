<?php

namespace Francerz\OAuth2;

use Francerz\Http\Tools\MessageHelper;
use Psr\Http\Message\MessageInterface;

class AccessToken implements \JsonSerializable
{

    public $accessToken;
    public $tokenType;
    public $expiresIn;
    public $refreshToken;

    private $scope = '';

    private $parameters = array();

    private $createTime;

    public static function fromHttpMessage(MessageInterface $message) : AccessToken
    {
        $at = MessageHelper::getContent($message);

        return new static(
            $at->access_token,
            $at->token_type,
            $at->expires_in,
            isset($at->refresh_token) ? $at->refresh_token : null,
            null, // createTime (not in standard)
        );
    }

    public function __construct(
        string $accessToken,
        string $tokenType = 'Bearer',
        int $expiresIn = 3600,
        ?string $refreshToken = null,
        ?int $createTime = null,
        string $scope = ''
    ) {
        $this->accessToken = $accessToken;
        $this->tokenType = $tokenType;
        $this->expiresIn = $expiresIn;
        $this->refreshToken = $refreshToken;
        $this->createTime = is_null($createTime) ? time() : $createTime;
        $this->scope = $scope;
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

    public function __toString()
    {
        return $this->tokenType . ' ' . $this->accessToken;
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
    public function getScope() : string
    {
        return $this->scope;
    }
    public function setScope(string $scope)
    {
        $this->scope = $scope;
    }
    public function getParameter(string $name)
    {
        if (array_key_exists($name, $this->parameters)) {
            return $this->parameters[$name];
        }
        return null;
    }
    public function setParameter(string $name, $value)
    {
        $this->parameters[$name] = $value;
    }
    public function getCreateTime() : int
    {
        return $this->createTime;
    }
    #endregion
}