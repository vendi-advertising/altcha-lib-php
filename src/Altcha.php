<?php

namespace AltchaOrg\Altcha;

use InvalidArgumentException;

class Altcha
{
    public const DEFAULT_MAX_NUMBER  = 1e6;
    public const DEFAULT_SALT_LENGTH = 12;
    public const DEFAULT_ALGORITHM   = Algorithm::SHA256;

    private static function randomBytes(int $length): string
    {
        return random_bytes($length);
    }

    private static function randomInt(int $max): int
    {
        return random_int(0, $max);
    }

    private static function hash(string $algorithm, string $data): string
    {
        switch ($algorithm) {
            case Algorithm::SHA1:
                return sha1($data, true);
            case Algorithm::SHA256:
                return hash('sha256', $data, true);
            case Algorithm::SHA512:
                return hash('sha512', $data, true);
            default:
                throw new InvalidArgumentException("Unsupported algorithm: $algorithm");
        }
    }

    public static function hashHex(string $algorithm, string $data): string
    {
        return bin2hex(self::hash($algorithm, $data));
    }

    private static function hmacHash(string $algorithm, string $data, string $key): string
    {
        switch ($algorithm) {
            case Algorithm::SHA1:
                return hash_hmac('sha1', $data, $key, true);
            case Algorithm::SHA256:
                return hash_hmac('sha256', $data, $key, true);
            case Algorithm::SHA512:
                return hash_hmac('sha512', $data, $key, true);
            default:
                throw new InvalidArgumentException("Unsupported algorithm: $algorithm");
        }
    }

    private static function hmacHex(string $algorithm, string $data, string $key): string
    {
        return bin2hex(self::hmacHash($algorithm, $data, $key));
    }

    /**
     * @param ChallengeOptions|array $options
     */
    public static function createChallenge($options): Challenge
    {
        if (is_array($options)) {
            $options = new ChallengeOptions($options);
        }

        $algorithm = $options->algorithm ?: self::DEFAULT_ALGORITHM;
        $maxNumber = $options->maxNumber ?: self::DEFAULT_MAX_NUMBER;
        $saltLength = $options->saltLength ?: self::DEFAULT_SALT_LENGTH;

        $params = $options->params;
        if ($options->expires) {
            $params['expires'] = $options->expires->getTimestamp();
        }

        $salt = $options->salt ?: bin2hex(self::randomBytes($saltLength));
        if (!empty($params)) {
            $salt .= '?' . http_build_query($params);
        }

        $number = $options->number ?: self::randomInt($maxNumber);

        $challenge = self::hashHex($algorithm, $salt . $number);

        $signature = self::hmacHex($algorithm, $challenge, $options->hmacKey);

        return new Challenge($algorithm, $challenge, $maxNumber, $salt, $signature);
    }

    /**
     * @param string|array $payload
     * @param string $hmacKey
     * @param bool $checkExpires
     * @return bool
     */
    public static function verifySolution($payload, string $hmacKey, bool $checkExpires = true): bool
    {
        if (is_string($payload)) {
            $payload = json_decode(base64_decode($payload), true, 512, JSON_THROW_ON_ERROR);
        }

        $payloadObject = new Payload($payload['algorithm'], $payload['challenge'], $payload['number'], $payload['salt'], $payload['signature']);

        $params = self::extractParams($payloadObject);
        if ($checkExpires && isset($params['expires'])) {
            $expireTime = (int)$params['expires'];
            if (time() > $expireTime) {
                return false;
            }
        }

        $challengeOptions = new ChallengeOptions([
            'algorithm' => $payloadObject->algorithm,
            'hmacKey' => $hmacKey,
            'number' => $payloadObject->number,
            'salt' => $payloadObject->salt,
        ]);

        $expectedChallenge = self::createChallenge($challengeOptions);

        return $expectedChallenge->challenge === $payloadObject->challenge &&
            $expectedChallenge->signature === $payloadObject->signature;
    }

    private static function extractParams(Payload $payload): array
    {
        $saltParts = explode('?', $payload->salt);
        if (count($saltParts) > 1) {
            parse_str($saltParts[1], $params);
            return $params;
        }
        return [];
    }

    public static function verifyFieldsHash(array $formData, array $fields, string $fieldsHash, string $algorithm): bool
    {
        $lines = [];
        foreach ($fields as $field) {
            $lines[] = $formData[$field] ?? '';
        }
        $joinedData = implode("\n", $lines);
        $computedHash = self::hashHex($algorithm, $joinedData);
        return $computedHash === $fieldsHash;
    }

    /**
     * @param string|array $payload
     * @param string $hmacKey
     * @return array
     */
    public static function verifyServerSignature($payload, string $hmacKey): array
    {
        if (is_string($payload)) {
            $payload = json_decode(base64_decode($payload), true, 512, JSON_THROW_ON_ERROR);
        }

        $payloadObject = new ServerSignaturePayload($payload['algorithm'], $payload['verificationData'], $payload['signature'], $payload['verified']);

        $hash = self::hash($payloadObject->algorithm, $payloadObject->verificationData);
        $expectedSignature = self::hmacHex($payloadObject->algorithm, $hash, $hmacKey);

        parse_str($payloadObject->verificationData, $params);

        $verificationData = new ServerSignatureVerificationData();
        $verificationData->classification = $params['classification'] ?? '';
        $verificationData->country = $params['country'] ?? '';
        $verificationData->detectedLanguage = $params['detectedLanguage'] ?? '';
        $verificationData->email = $params['email'] ?? '';
        $verificationData->expire = (int)($params['expire'] ?? 0);
        $verificationData->fields = explode(',', $params['fields'] ?? '');
        $verificationData->fieldsHash = $params['fieldsHash'] ?? '';
        $verificationData->reasons = explode(',', $params['reasons'] ?? '');
        $verificationData->score = (float)($params['score'] ?? 0);
        $verificationData->time = (int)($params['time'] ?? 0);
        $verificationData->verified = ($params['verified'] ?? 'false') === 'true';

        $now = time();
        $isVerified = $payloadObject->verified && $verificationData->verified &&
            $verificationData->expire > $now &&
            $payloadObject->signature === $expectedSignature;

        return [$isVerified, $verificationData];
    }

    public static function solveChallenge(string $challenge, string $salt, string $algorithm, int $max = 1000000, int $start = 0): ?Solution
    {
        $startTime = microtime(true);

        for ($n = $start; $n <= $max; $n++) {
            $hash = self::hashHex($algorithm, $salt . $n);
            if ($hash === $challenge) {
                $took = microtime(true) - $startTime;
                return new Solution($n, $took);
            }
        }

        return null;
    }
}
