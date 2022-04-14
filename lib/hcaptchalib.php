<?php
/**
 * This is a PHP library that handles calling hCaptcha.
 *    - See also
 *          https://docs.hcaptcha.com/
 *    - Get a hCaptcha Site/Secret Key
 *          https://dashboard.hcaptcha.com/
 *
 * THIS IS AN ADJUSTED VERSION SUPPORTING hCaptcha
 *
 * based on recaptchalib.php (php_1.1.1)
 *   from https://developers.google.com/recaptcha/docs/php
 *
 * @copyright Copyright (c) 2014, Google Inc.
 * @link      http://www.google.com/recaptcha
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * hCaptcha client
 */
class ReCaptcha
{
    private static $version = "php_1.1.1";
    private static $signupUrl = "https://dashboard.hcaptcha.com/";
    private static $siteVerifyUrl = "https://hcaptcha.com/siteverify";
    private $_secret;
    private $_options;

    /**
     * Constructor.
     *
     * @param string $secret shared secret between site and ReCAPTCHA server.
     * @param array  $extra_options Extra options to pass to the stream context.
     */
    function __construct($secret, $extra_options = null)
    {
        if (empty($secret)) {
            die('To use hCaptcha you must get an API key from <a href="' .
                self::$signupUrl . '">' . self::$signupUrl . '</a>');
        }

        $this->_secret = $secret;
        $this->_options = $extra_options;
    }


    /**
     * Submit the POST request with the specified parameters.
     *
     * @param array $params Request parameters
     * @return string Body of the hCaptcha response
     */
    private function _submit($params)
    {
        // PHP 5.6.0 changed the way you specify the peer name for SSL context options.
        // Using "CN_name" will still work, but it will raise deprecated errors.
        $peer_key = version_compare(PHP_VERSION, '5.6.0', '<') ? 'CN_name' : 'peer_name';
        $options  = array(
            'http' => array(
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($params, '', '&'),
                // Force the peer to validate (not needed in 5.6.0+, but still works)
                'verify_peer' => true,
                $peer_key => 'hcaptcha.com',
            )
        );

        if ($this->_options) {
            $options = self::mergeOptions($options, $this->_options);
        }

        // REMEMBER: this is only for this kind of RequestMethod\Post
        if (isset($options['http']['proxy'])
            && strpos($options['http']['proxy'], 'tcp://') === false) {
            $options['http']['proxy'] = 'tcp://' . $options['http']['proxy'];
        }

        $context = stream_context_create($options);
        return file_get_contents(self::$siteVerifyUrl, false, $context);
    }

    /**
     * Recursively merge options without appending values.
     *
     * @param  array  $opts1 Options array (the default options)
     * @param  array  $opts2 Options array (the given options)
     * @return array         The merged options
     */
    private static function mergeOptions($opts1, $opts2)
    {
        if (is_array($opts2)) {
            foreach ($opts2 as $key => $val) {
                $opts1[$key] = (
                    is_array($val) && isset($opts1[$key]) && is_array($opts1[$key])
                    ? self::mergeOptions($opts1[$key], $val) : $val
                );
            }
        }
        return $opts1;
    }

    /**
     * Calls the hCaptcha siteverify API to verify whether the user passes
     * CAPTCHA test. (hCaptcha version php_1.1.1)
     *
     * @param string $response The value of 'h-captcha-response' in the submitted form.
     * @param string $remoteIp The end user's IP address.
     * @param string $sitekey assigned site key
     * @return ReCaptchaResponse Response from the service.
     */
    public function verify($response, $remoteIp = null, $sitekey = null)
    {
        if (empty($response)) { // Discard empty solution submissions
            return new ReCaptchaResponse(false, array('missing-input'));
        }

        $params = array('secret'   => $this->_secret,
                        'sitekey'  => $sitekey,
                        'remoteip' => $remoteIp,
                        'response' => $response
                        );

        $rawResponse = $this->_submit($params);

        return ReCaptchaResponse::fromJson($rawResponse);
    }
}


/**
 * The response returned from the service.
 */
class ReCaptchaResponse
{
    public $success;
    public $errorCodes;

    /**
     * Constructor.
     *
     * @param boolean $success
     * @param array $errorCodes
     */
    function __construct($success, $errorCodes=array())
    {
        $this->success = $success;
        $this->errorCodes = $errorCodes;
    }

    /**
     * Build the response from the expected JSON returned by the service.
     *
     * @param string $json
     * @return ReCaptchaResponse
     */
    public static function fromJson($json)
    {
        $responseData = json_decode($json, true);

        if (!$responseData) {
            $reCaptchaResponse = new ReCaptchaResponse(false, array('invalid-json'));
        }
        else if (isset($responseData['success']) && $responseData['success'] == true) {
            $reCaptchaResponse = new ReCaptchaResponse(true);
        }
        else if (isset($responseData['error-codes']) && is_array($responseData['error-codes'])) {
            $reCaptchaResponse = new ReCaptchaResponse(false, $responseData['error-codes']);
        }
        else {
            $reCaptchaResponse = new ReCaptchaResponse(false);
        }

        return $reCaptchaResponse;
    }
}

?>
