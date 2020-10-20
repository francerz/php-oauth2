<?php

namespace Francerz\OAuth2\AuthServer;

class Client implements ClientInterface
{
    private $client_id;
    private $client_secret;
    private $confidential;

    private $params = array();
    
    public function __construct(string $client_id, string $client_secret = null, bool $confidential = false)
    {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->confidential = $confidential;
    }

    public function getClientId(): string
    {
        return $this->client_id;
    }
    public function getClientSecret(): string
    {
        return $this->client_secret;
    }
    public function isConfidential(): bool
    {
        return $this->confidential;
    }

    public function withParam(string $name, $value) : Client
    {
        $new = clone $this;
        $new->params[$name] = $value;
        return $new;
    }

    public function getParam(string $name)
    {
        if (array_key_exists($name, $this->params)) {
            return $this->params[$name];
        }
    }
}