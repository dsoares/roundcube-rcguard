<?php

/*
 * rcguard plugin
 * Version HEAD
 *
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
 *
 */

define('RCGUARD_RECAPTCHA_SUCCESS', 0);
define('RCGUARD_RECAPTCHA_FAILURE', 1);

class rcguard extends rcube_plugin
{
  function init()
  {
    $this->add_hook('template_object_loginform', array($this, 'loginform'));
    $this->add_hook('authenticate', array($this, 'authenticate'));
    $this->add_hook('login_after', array($this, 'login_after'));
    $this->add_hook('login_failed', array($this, 'login_failed'));
  }

  function loginform($loginform)
  {
    $this->load_config();
    $rcmail = rcmail::get_instance();
    $client_ip = $_SERVER['REMOTE_ADDR'];

    $query = $rcmail->db->query(
      "SELECT " . $this->unixtimestamp('last') . " AS last
       FROM rcguard
       WHERE ip = ? AND hits >= ?",
      $client_ip, $rcmail->config->get('failed_attempts'));
    $result = $rcmail->db->fetch_assoc($query);

    if ((!$result || $this->delete_rcguard($result, $client_ip)) &&
      $rcmail->config->get('failed_attempts') != 0)
      return $loginform;

    return $this->show_recaptcha($loginform);
  }

  function authenticate($args)
  {
    $this->load_config();
    $this->add_texts('localization/');
    $rcmail = rcmail::get_instance();
    $client_ip = $_SERVER['REMOTE_ADDR'];

    $query = $rcmail->db->query(
      "SELECT ip
       FROM rcguard
       WHERE ip = ? AND hits >= ?",
      $client_ip, $rcmail->config->get('failed_attempts'));
    $result = $rcmail->db->fetch_assoc($query);

    if (!$result && $rcmail->config->get('failed_attempts') != 0)
      return $args;

    if ($rcmail->config->get('pl_plugin')) {
      if (!empty($_COOKIE[$rcmail->config->get('pl_cookie_name')])) {
        $args = $this->pl_authenticate($args);
        return $args;
      }
    }

    if (($challenge = $_POST['recaptcha_challenge_field'])
      && ($response = $_POST['recaptcha_response_field'])) {
      if ($this->verify_recaptcha($client_ip, $challenge, $response)) {
        $this->log_recaptcha(RCGUARD_RECAPTCHA_SUCCESS, $args['user']);

        return $args;
      }
      else {
        $this->log_recaptcha(RCGUARD_RECAPTCHA_FAILURE, $args['user']);

        $rcmail->output->show_message('rcguard.recaptchafailed', 'error');
        $rcmail->output->set_env('task', 'login');
        $rcmail->output->send('login');

        exit;
      }
    }
    else {
      $this->log_recaptcha(RCGUARD_RECAPTCHA_FAILURE, $args['user']);

      $rcmail->output->show_message('rcguard.recaptchaempty', 'error');
      $rcmail->output->set_env('task', 'login');
      $rcmail->output->send('login');

      exit;
    }
  }

  function login_after($args)
  {
    $client_ip = $_SERVER['REMOTE_ADDR'];

    $this->delete_rcguard('', $client_ip, true);

    return $args;
  }

  function login_failed($args)
  {
    $rcmail = rcmail::get_instance();

    $client_ip = $_SERVER['REMOTE_ADDR'];

    $now = date('Y-m-d H:i:s');

    $query = $rcmail->db->query(
      "SELECT hits
       FROM rcguard
       WHERE ip = ?",
      $client_ip);
    $result = $rcmail->db->fetch_assoc($query);

    if ($result)
      $this->update_rcguard($now, $result['hits'], $client_ip);
    else
      $this->insert_rcguard($client_ip, $now);
  }

  private function insert_rcguard($client_ip, $now)
  {
    $rcmail = rcmail::get_instance();

    $query = $rcmail->db->query(
      "INSERT INTO rcguard
       (ip, first, last, hits)
       VALUES (?, ?, ?, ?)",
      $client_ip, $now, $now, 1);
  }

  private function update_rcguard($now, $hits, $client_ip)
  {
    $rcmail = rcmail::get_instance();

    $query = $rcmail->db->query(
      "UPDATE rcguard
       SET last = ?, hits = ?
       WHERE ip = ?",
      $now, $hits + 1, $client_ip);
  }

  private function delete_rcguard($result, $client_ip, $force = false)
  {
    $this->load_config();
    $rcmail = rcmail::get_instance();

    if ($force) {
      $query = $rcmail->db->query(
        "DELETE FROM rcguard
        WHERE ip = ?",
        $client_ip);

      $this->flush_rcguard();

      return;
    }

    $last = $result['last'];

    if ($last + $rcmail->config->get('expire_time') * 60 < time()) {
      $this->flush_rcguard();

      return true;
    }
    else
      return false;
  }

  private function flush_rcguard()
  {
    $this->load_config();
    $rcmail = rcmail::get_instance();

    $query = $rcmail->db->query(
      "DELETE FROM rcguard
       WHERE " . $this->unixtimestamp('last') . " + ? < " . $this->unixtimestamp('NOW()'),
      $rcmail->config->get('expire_time') * 60);
  }

  private function show_recaptcha($loginform)
  {
    $this->load_config();
    $rcmail = rcmail::get_instance();
    $recaptcha_api = 'http://www.google.com/recaptcha/api';
    $recaptcha_api_secure = 'https://www.google.com/recaptcha/api';

    $skin_path = $this->local_skin_path();
    $this->include_stylesheet($skin_path . '/rcguard.css');
    $this->include_script('rcguard.js');

    $src = sprintf("%s/challenge?k=%s",
        $rcmail->config->get('recaptcha_https') ? $recaptcha_api_secure : $recaptcha_api,
        $rcmail->config->get('recaptcha_publickey'));

    $script = html::tag('script', array('type' => "text/javascript", 'src' => $src));

    $tmp = $loginform['content'];
    $tmp = str_ireplace('</tbody>',
      '<tr><td class="title"><div id="rcguard"><div id="recaptcha">' . $script . '</div></div>
</td>
</tr>
</tbody>', $tmp);
    $loginform['content'] = $tmp;

    return $loginform;
  }

  private function verify_recaptcha($client_ip, $challenge, $response)
  {
    $this->load_config();
    $rcmail = rcmail::get_instance();
    $privatekey = $rcmail->config->get('recaptcha_privatekey');

    require_once($this->home . '/lib/recaptchalib.php');
    $resp = null;
    $error = null;

    $resp = recaptcha_check_answer($privatekey, $client_ip, $challenge, $response);

    if ($resp->is_valid)
      return true;
    else
      return false;
  }

  private function log_recaptcha($log_type, $username)
  {
    $this->load_config();
    $rcmail = rcmail::get_instance();
    $client_ip = $_SERVER['REMOTE_ADDR'];
    $username = (empty($username)) ? 'empty username' : $username;

    if (!$rcmail->config->get('recaptcha_log'))
      return;

    switch ($log_type) {
      case RCGUARD_RECAPTCHA_SUCCESS:
        $log_entry = $rcmail->config->get('recaptcha_log_success');
        break;
      case RCGUARD_RECAPTCHA_FAILURE:
        $log_entry = $rcmail->config->get('recaptcha_log_failure');
        break;
      default:
        $log_entry = $rcmail->config->get('recaptcha_log_unknown');
    }

    if (empty($log_entry))
      return;

    $log_entry = str_replace(array('%r', '%u'), array($client_ip, $username), $log_entry);

    write_log('rcguard', $log_entry);
  }

  private function unixtimestamp($field)
  {
    $rcmail = rcmail::get_instance();

    switch ($rcmail->db->db_provider) {
      case 'pgsql':
        return "EXTRACT (EPOCH FROM $field)";
      default:
        return "UNIX_TIMESTAMP($field)";
    }
  }

  private function pl_authenticate($args) {
    $this->load_config();
    $rcmail = rcmail::get_instance();

    // Code from persistent login plugin
    $plain_token = $rcmail->decrypt($_COOKIE[$this->cookie_name]);
    $token_parts = explode('|', $plain_token);

    if (!empty($token_parts) && is_array($token_parts) && count($token_parts == 5)) {
      if (time() <= $token_parts[4]) {
        $args['user'] = $token_parts[1];
        $args['pass'] = $rcmail->decrypt($token_parts[2]);
        $args['host'] = $token_parts[3];
        $args['cookiecheck'] = false;
        $args['valid'] = true;
      }
    }

    return $args;
  }
}

?>
