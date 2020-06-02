<?php

namespace Rinordreshaj\AppleSignIn;

use GuzzleHttp\Client;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

class AppleSignIn
{
    private static $apple_keys_service = "https://appleid.apple.com/auth/keys";
    private static $n = null;
    private static $e = null;

    public static function verify_signature($token)
    {
        list($header, $claims, $signature) = explode('.', $token);

        $decoded_header = self::decodeFragment($header);

        $decoded_claims = self::decodeFragment($claims);

        if($decoded_claims['iss'] !== "https://appleid.apple.com")
        {
            return false;
        }

        if($decoded_claims['aud'] != config("apple_sign_in.package_name") && $decoded_claims['aud'] != config("apple_sign_in.service_name"))
        {
            return false;
        }

        if($decoded_claims['exp'] - time() < 0)
        {
            return false;
        }

        self::setKeys($decoded_header['kid']);

        // Format data
        $signature = self::sanitizeAndBase64Decode($signature);
        self::$n = self::sanitizeAndBase64Decode(self::$n);
        self::$e = self::sanitizeAndBase64Decode(self::$e);

        $rsa = new RSA();

        $rsa->loadKey([
            'n' => new BigInteger(self::$n, 256),
            'e' => new BigInteger(self::$e, 256),
        ]);
        $rsa->setHash('sha256');

        $rsa->setSignatureMode(OPENSSL_ALGO_SHA256);

        $signature_to_verify = $header . '.' . $claims;

        return $rsa->_rsassa_pkcs1_v1_5_verify($signature_to_verify, $signature);
    }

    protected static function decodeFragment($value)
    {
        return (array) json_decode(base64_decode($value));
    }

    protected static function sanitizeAndBase64Decode($str)
    {
        $str = str_replace(['-','_'], ['+','/'], $str);

        return base64_decode($str);
    }

    protected static function call_url($url, $method)
    {
        try
        {
            $client = new Client();

            $response = $client->request($method ?? 'POST', $url);

            if ($response->getStatusCode() == 200)
            {
                return json_decode($response->getBody(), true);
            }
            else
            {
                throw new \Exception("Apple sign in error: Request to apple server failed");
            }
        }
        catch (\Exception $exception)
        {
            throw new \Exception("Apple sign in error: Request to apple server failed");
        }
    }

    protected static function setKeys($kid)
    {
        $response = self::call_url(self::$apple_keys_service, 'GET');

        foreach($response['keys'] as $key)
        {
            if($key['kid'] == $kid)
            {
                self::$n = $key['n'];
                self::$n = $key['e'];
            }
        }
    }
}