<?php
/**
 * Roundcube rcguard plugin.
 *
 * Roundcube plugin to provide Google reCAPTCHA service to Roundcube.
 *
 * @version 1.3.1
 * @author Diana Soares
 *
 * Copyright (c) Diana Soares. All rights reserved.
 * Copyright (c) 2010-2012 Denny Lin. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
define('RCGUARD_RECAPTCHA_SUCCESS', 0);
define('RCGUARD_RECAPTCHA_FAILURE', 1);

class rcguard extends rcube_plugin
{
    public $task = 'login';
    private $table_name;
    private $rc;

    public function init()
    {
        $this->load_config('config.inc.php.dist');
        $this->load_config();

        $this->rc = rcmail::get_instance();

        $ignore_ips = $this->rc->config->get('rcguard_ignore_ips', []);
        $client_ip = $this->get_client_ip();
        $whitelisted = false;

        if (in_array($client_ip, $ignore_ips)) {
            $whitelisted = true;
        } else {
            foreach ($this->rc->config->get('recaptcha_whitelist', []) as $network) {
                if ($this->cidr_match($client_ip, $network)) {
                    $whitelisted = true;
                    break;
                }
            }
        }

        if (!$whitelisted) {
            $this->table_name = $this->rc->db->table_name('rcguard', true);
            $this->add_hook('template_object_loginform', [$this, 'loginform']);
            $this->add_hook('authenticate', [$this, 'authenticate']);
            $this->add_hook('login_after', [$this, 'login_after']);
            $this->add_hook('login_failed', [$this, 'login_failed']);
        }
    }

    public function loginform($loginform)
    {
        $rcmail = rcmail::get_instance();

        $client_ip = $this->get_client_ip();
        $failed_attempts = $rcmail->config->get('failed_attempts', 3);

        if ($failed_attempts > 0) {
            $query = sprintf(
                'SELECT %s AS lasttime, %s AS nowtime FROM %s WHERE ip = ? AND hits >= ?',
                $this->unixtimestamp('last'),
                $this->unixtimestamp('NOW()'),
                $this->table_name
            );

            $query = $rcmail->db->query($query, $client_ip, $failed_attempts);
            $result = $rcmail->db->fetch_assoc($query);
            $expire = (int) ($rcmail->config->get('expire_time', 30)) * 60;

            if ($result && $result['lasttime'] + $expire < $result['nowtime']) {
                $this->flush_rcguard();
                $result = 0;
            }

            if (!$result) {
                return $loginform;
            }
        }

        return $this->show_recaptcha($loginform);
    }

    public function authenticate($args)
    {
        $rcmail = rcmail::get_instance();

        $client_ip = $this->get_client_ip();
        $failed_attempts = $rcmail->config->get('failed_attempts');

        $query = $rcmail->db->query(
            'SELECT ip FROM ' . $this->table_name . ' WHERE ip = ? AND hits >= ?',
            [$client_ip, $failed_attempts]
        );
        $result = $rcmail->db->fetch_assoc($query);

        if (!$result && $failed_attempts > 0) {
            return $args;
        }

        $msg = 'rcguard.recaptchaempty';
        $response = rcube_utils::get_input_value('g-recaptcha-response', rcube_utils::INPUT_POST);

        if ($response) {
            if ($this->verify_recaptcha($response, $client_ip)) {
                $this->log_recaptcha(RCGUARD_RECAPTCHA_SUCCESS, $args['user']);

                return $args;
            }

            $msg = 'rcguard.recaptchafailed';
        }

        $this->log_recaptcha(RCGUARD_RECAPTCHA_FAILURE, $args['user']);
        $this->add_texts('localization');
        $rcmail->output->show_message($msg, 'error');
        $rcmail->output->set_env('task', 'login');
        $rcmail->output->send('login');

        return null;
    }

    public function login_after($args)
    {
        if ($this->rc->config->get('rcguard_reset_after_success', true)) {
            $this->delete_rcguard($this->get_client_ip());
        }

        return $args;
    }

    public function login_failed($args)
    {
        $client_ip = $this->get_client_ip();

        $query = $this->rc->db->query(
            'SELECT hits FROM ' . $this->table_name . ' WHERE ip = ?',
            $client_ip
        );
        $result = $this->rc->db->fetch_assoc($query);

        if ($result) {
            $this->update_rcguard($client_ip);
        } else {
            $this->insert_rcguard($client_ip);
        }
    }

    private function insert_rcguard($client_ip)
    {
        $this->rc->db->query(
            'INSERT INTO ' . $this->table_name . ' (ip, first, last, hits) ' .
            'VALUES (?, ' . $this->unixnow() . ', ' . $this->unixnow() . ', 1)',
            $client_ip
        );
    }

    private function update_rcguard($client_ip)
    {
        $this->rc->db->query(
            'UPDATE ' . $this->table_name . ' SET last = ' . $this->unixnow() .
            ', hits = hits + 1 WHERE ip = ?',
            $client_ip
        );
    }

    private function delete_rcguard($client_ip)
    {
        $this->rc->db->query(
            'DELETE FROM ' . $this->table_name . ' WHERE ip = ?',
            $client_ip
        );
        $this->flush_rcguard();
    }

    private function flush_rcguard()
    {
        $this->rc->db->query(
            'DELETE FROM ' . $this->table_name . ' WHERE ' .
            $this->unixtimestamp('last') . ' + ? < ' . $this->unixtimestamp('NOW()'),
            (int) ($this->rc->config->get('expire_time')) * 60
        );
    }

    private function unixtimestamp($field)
    {
        switch ($this->rc->db->db_provider) {
        case 'sqlite':
            $ts = (stripos($field, 'NOW()') !== false) ? $this->unixnow() : $field;
            break;
        case 'pgsql':
        case 'postgres':
            $ts = "EXTRACT (EPOCH FROM {$field})";
            break;
        default:
            $ts = "UNIX_TIMESTAMP({$field})";
        }

        return $ts;
    }

    private function unixnow()
    {
        switch ($this->rc->db->db_provider) {
        case 'sqlite':
            $now = "strftime('%s', 'now')";
            break;
        default:
            $now = 'NOW()';
        }

        return $now;
    }

    private function _deprecated_config_var_api()
    {
        $config = $this->rc->config;

        $url = $config->get('recaptcha_api_secure', false);
        if ($url && ($config->get('recaptcha_https', true) || rcube_utils::https_check())) {
            $this->rc->config->set('recaptcha_api_url', $url);
        } else {
            $url = $config->get('recaptcha_api', false);
            if ($url) {
                $this->rc->config->set('recaptcha_api_url', $url);
            }
        }
    }

    private function show_recaptcha($loginform)
    {
        $this->_deprecated_config_var_api();

        $api_version = $this->rc->config->get('recaptcha_api_version', 'v2');

        if ($api_version === 'v3') {
            $loginform['content'] .= $this->show_recaptcha_v3();
        } elseif ($api_version === 'v2invisible') {
            $loginform['content'] .= $this->show_recaptcha_v2invisible();
        } else {
            $html = $this->show_recaptcha_v2();

            $skin_path = $this->local_skin_path();
            $this->include_stylesheet($skin_path . '/rcguard.css');

            if (strpos($skin_path, '/elastic') !== false) {
                $tag = '</table>';
                $html = '<div class="form-group row">' . $html . '</div>';
            } else {
                $tag = '</tbody>';
                $html = '<tr><td colspan="2">' . $html . '</td></tr>';
            }

            $loginform['content'] = str_ireplace($tag, $tag . $html, $loginform['content']);
        }

        return $loginform;
    }

    private function show_recaptcha_v3()
    {
        $api = $this->rc->config->get('recaptcha_api_url');
        $src = sprintf('%s?render=%s', $api, $this->rc->config->get('recaptcha_publickey'));
        $this->include_script($src);

        $script = sprintf(
            'grecaptcha.ready(function(){' .
            "    grecaptcha.execute('%s',{action:'login'}).then(function(token) {" .
            "        $('#gtoken').val(token);" .
            '});});',
            $this->rc->config->get('recaptcha_publickey')
        );
        $this->rc->output->add_script($script, 'docready');

        return '<input type="hidden" id="gtoken" name="g-recaptcha-response" value="">';
    }

    private function show_recaptcha_v2invisible()
    {
        $script = 'grecaptcha.ready(function(){grecaptcha.execute();});';
        $this->rc->output->add_script($script, 'docready');

        return $this->show_recaptcha_v2('invisible');
    }

    private function show_recaptcha_v2($size = null)
    {
        $api = $this->rc->config->get('recaptcha_api_url');
        $src = sprintf('%s?hl=%s', $api, $this->rc->user->language);
        $this->include_script($src);

        $html = sprintf(
            '<div class="g-recaptcha" ' .
            'data-sitekey="%s" data-theme="%s" data-size="%s"></div>',
            $this->rc->config->get('recaptcha_publickey'),
            $this->rc->config->get('recaptcha_theme'),
            $size ?: $this->rc->config->get('recaptcha_size')
        );

        return $html;
    }

    private function verify_recaptcha($response, $client_ip = null)
    {
        $config = $this->rc->config;

        if (!$config->get('recaptcha_send_client_ip', false)) {
            $client_ip = null;
        }

        $options = null;

        if ($proxy = $config->get('recaptcha_proxy', false)) {
            $options = [
                'http' => [
                    'proxy' => $proxy,
                    'request_fulluri' => true,
                ],
            ];

            if ($auth = $config->get('recaptcha_proxy_auth', false)) {
                $auth = base64_encode($auth);
                $options['http']['header'] = "Proxy-Authorization: Basic {$auth}";
            }
        }

        require_once $this->home . '/lib/recaptchalib.php';

        $reCaptcha = new ReCaptcha($config->get('recaptcha_privatekey'), $options);
        $resp = $reCaptcha->verify($response, $client_ip);

        return $resp != null && $resp->success;
    }

    private function log_recaptcha($log_type, $username)
    {
        $config = $this->rc->config;

        if (!$config->get('recaptcha_log', false)) {
            return;
        }

        $client_ip = $this->get_client_ip();
        $username = (empty($username)) ? 'empty username' : $username;

        switch ($log_type) {
        case RCGUARD_RECAPTCHA_SUCCESS:
            $log_entry = $config->get('recaptcha_log_success');
            break;
        case RCGUARD_RECAPTCHA_FAILURE:
            $log_entry = $config->get('recaptcha_log_failure');
            break;
        default:
            $log_entry = $config->get('recaptcha_log_unknown');
        }

        if (!empty($log_entry)) {
            $log_entry = str_replace(['%r', '%u'], [$client_ip, $username], $log_entry);
            rcube::write_log('rcguard', $log_entry);
        }
    }

    private function get_client_ip()
    {
        $prefix = $this->rc->config->get('rcguard_ipv6_prefix', 0);
        $client_ip = rcube_utils::remote_addr();

        // process only if prefix is sane and it's an IPv6 address
        if (is_int($prefix) && $prefix > 16 && $prefix < 128 &&
            filter_var($client_ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6) !== false) {
            // construct subnet mask
            $mask_string = str_repeat('1', $prefix) . str_repeat('0', 128 - $prefix);
            $mask_split = str_split($mask_string, 16);
            foreach ($mask_split as $item) {
                $item = base_convert($item, 2, 16);
            }
            $mask_hex = implode(':', $mask_split);

            // return network part
            return inet_ntop(inet_pton($client_ip) & inet_pton($mask_hex));
        }

        // fall back: return unaltered client IP
        return $client_ip;
    }

    /**
     * Check an IP against a value in CIDR notation.
     *
     * @param  string $ip   IP to check
     * @param  string $cidr IP or network in CIDR notation
     * @return bool
     */
    private function cidr_match($ip, $cidr)
    {
        if (strpos($cidr, '/') === false) {
            $cidr .= '/32';
        }

        list($subnet, $bits) = explode('/', $cidr);
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet &= $mask; // nb: in case the supplied subnet wasn't correctly aligned

        return ($ip & $mask) == $subnet;
    }
}
