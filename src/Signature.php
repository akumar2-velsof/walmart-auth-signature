<?php
namespace Walmart\Auth;

use phpseclib\Crypt\RSA;

class Signature
{
    /**
     * @var string Consumer ID provided by Developer Portal
     */
    public $consumerId;

    /**
     * @var string Base64 Encoded Private Key provided by Developer Portal
     */
    public $privateKey;

    /**
     * @var string URL of API request being made
     */
    public $requestUrl;

    /**
     * @var string HTTP request method for API call (GET/POST/PUT/DELETE/OPTIONS/PATCH)
     */
    public $requestMethod;

    /**
     * You may optionally instantiate as an object. This is useful for repeated calls to getSignature();
     * @param string $consumerId
     * @param string $privateKey
     * @param string $requestUrl
     * @param string $requestMethod
     */
    public function __construct($consumerId, $privateKey, $requestUrl, $requestMethod)
    {
        $this->consumerId = $consumerId;
        $this->privateKey = $privateKey;
        $this->requestUrl = $requestUrl;
        $this->requestMethod = $requestMethod;
    }

    /**
     * Get signature with optional timestamp. If using Signature class as object, you can repeatedly call this
     * method to get a new signature without having to provide $consumerId, $privateKey, $requestUrl, $requestMethod
     * every time.
     * @param string|null $timestamp
     * @return string
     * @throws \Exception
     */
    public function getSignature($timestamp=null)
    {
        if(is_null($timestamp) || !is_numeric($timestamp)){
            $timestamp = self::getMilliseconds();
        }
        return self::calculateSignature(
            $this->consumerId,
            $this->privateKey,
            $this->requestUrl,
            $this->requestMethod,
            $timestamp
        );
    }

    /**
     * Static method for quick calls to calculate a signature.
     * @link https://developer.walmartapis.com/#authentication
     * @param string $consumerId
     * @param string $privateKey
     * @param string $requestUrl
     * @param string $requestMethod
     * @param string|null $timestamp
     * @return string
     * @throws \Exception
     */
    public static function calculateSignature($consumerId, $privateKey, $requestUrl, $requestMethod, $timestamp=null)
    {
        $token_url = "https://marketplace.walmartapis.com/v3/token";
        $authorization = base64_encode($consumerId . ":" . $privateKey);
        $qos = uniqid();
        $ch = curl_init();
        $options = array(
            CURLOPT_URL => $token_url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_HEADER => false,
            CURLOPT_POST => 1,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_POSTFIELDS => "grant_type=client_credentials",
            CURLOPT_HTTPHEADER => array(
                "Authorization: Basic " . $authorization,
                "Content-Type: application/x-www-form-urlencoded",
                "Accept: application/json",
                "WM_SVC.NAME: Walmart Marketplace",
                "WM_QOS.CORRELATION_ID: " . $qos,
                "WM_SVC.VERSION: 1.0.0"
            ),
        );
        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);
        $array = json_decode($response, true);
        if(!empty($array['access_token'])) {
            return $array['access_token'];
        } else {
            throw new \Exception("Token not received", 1446780146);
        }
    }

    /**
     * Get current timestamp in milliseconds
     * @return float
     */
    public static function getMilliseconds()
    {
        return round(microtime(true) * 1000);
    }
}