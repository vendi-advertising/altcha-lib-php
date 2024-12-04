<?php

namespace AltchaOrg\Altcha;

class Challenge
{
    public string $algorithm;
    public string $challenge;
    public int $maxnumber;
    public string $salt;
    public string $signature;

    public function __construct(string $algorithm, string $challenge, int $maxNumber, string $salt, string $signature)
    {
        $this->algorithm = $algorithm;
        $this->challenge = $challenge;
        $this->maxnumber = $maxNumber;
        $this->salt = $salt;
        $this->signature = $signature;
    }
}
