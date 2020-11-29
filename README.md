# Roundcube plugin rcguard

## Introduction

This plugin logs failed login attempts and requires users to go through
a reCAPTCHA verification process when the number of failed attempts go
too high. It provides protection against automated attacks.

Failed attempts are logged by IP and stored in a database table.
IPs are also released after a certain expire amount of time.


## Installation

<big>**IMPORTANT: This plugin requires reCAPTCHA API keys to work properly.**</big>
<br>These can be obtained from https://www.google.com/recaptcha.


#### With Composer

Add this plugin `dsoares/rcguard` to the `require` section of your Roundcube
`composer.json`, run composer update and enable rcguard in the main Roundcube
configuration file.
<br>OR just run:

    composer require dsoares/rcguard

Copy `config.inc.php.dist` to `config.inc.php` and modify as necessary.

#### Manually

Place the contents of this directory under `plugins/rcguard` and enable rcguard
in the main Roundcube configuration file.

Copy `config.inc.php.dist` to `config.inc.php` and modify as necessary.

Use the files under `SQL/` to create the database schema required for
rcguard. The table should be created in the database used by Roundcube.
**NOTE**: If you use the Roundcube `db_prefix` config option, you must rename
the table `rcguard` accordingly.


## Customizing reCAPTCHA

You may customize the following in the `config.inc.php` file:

- the API version: `v3`, `v2invisible` or `v2`;
- the v2 widget theme: `light` or `dark`;
- the v2 widget size: `normal` or `compact`.

For more information about the widget please check the [documentation about reCAPTCHA][recaptcha-doc].

The plugin configuration file has several other options you may configure, please take at look.

Since May 2018, you can define a proxy (anonymous or authenticated) to request the recaptcha widget.


## Supported databases

- MySQL
- PostgreSQL
- SQLite


## Contact

The original author of this plugin was [Denny Lin][dennylin]. I forked it some
years ago to 1) use reCAPTCHA v2.0, 2) add the larry skin and 3) because the project
issues were taking too long to be answered. Also, the original project was not
updated since 2015 and many things have changed in the meantime in Roundcube's API.

I will maintain this project because i need it working with the latest
version of Roundcube.

Comments and suggestions are welcome (preferentially via issues).

Email: [Diana Soares][email]

[email]: mailto:diana.soares@gmail.com
[dennylin]: https://github.com/dennylin93
[recaptcha-doc]: https://developers.google.com/recaptcha/intro


## License

This plugin is distributed under the GPL-3.0+ license.

This plugin also contains a PHP library for reCAPTCHA that is
distributed under its own license. See the library file for the exact details.

