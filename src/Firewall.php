<?php

namespace FacebookAnonymousPublisher\Firewall;

use GeoIp2\Database\Reader;
use Vectorface\Whip\Whip;

class Firewall
{
    /**
     * @var Models\Firewall
     */
    protected $model;

    /**
     * @var Reader
     */
    protected $reader;

    /**
     * @var Whip
     */
    protected $whip;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->model = new Models\Firewall;

        $this->reader = new Reader(__DIR__.'/../db/GeoLite2-Country.mmdb');

        $this->whip = new Whip(Whip::CLOUDFLARE_HEADERS | Whip::REMOTE_ADDR, $this->whiteList());
    }

    /**
     * Get the Cloudflare white list IP list.
     *
     * @return array
     */
    protected function whiteList()
    {
        return [
            Whip::CLOUDFLARE_HEADERS => [
                Whip::IPV4 => [
                    '103.21.244.0/22',
                    '103.22.200.0/22',
                    '103.31.4.0/22',
                    '104.16.0.0/12',
                    '108.162.192.0/18',
                    '131.0.72.0/22',
                    '141.101.64.0/18',
                    '162.158.0.0/15',
                    '172.64.0.0/13',
                    '173.245.48.0/20',
                    '188.114.96.0/20',
                    '190.93.240.0/20',
                    '197.234.240.0/22',
                    '198.41.128.0/17',
                    '199.27.128.0/21',
                ],
                Whip::IPV6 => [
                    '2400:cb00::/32',
                    '2405:8100::/32',
                    '2405:b500::/32',
                    '2606:4700::/32',
                    '2803:f800::/32',
                    '2c0f:f248::/32',
                    '2a06:98c0::/29',
                ],
            ],
        ];
    }

    /**
     * Get the valid IP address or false if no valid IP address was found.
     *
     * @return string|false
     */
    public function ip()
    {
        return $this->whip->getValidIpAddress();
    }

    /**
     * Determine the request ip address is banned or not.
     *
     * @return bool
     */
    public function isBanned()
    {
        if (session('isBan', false)) {
            $this->ban();

            return true;
        }

        $banned = $this->model
            ->all(['ip'])
            ->search(function (Models\Firewall $firewall) {
                return $this->ip() === $firewall->getAttribute('ip');
            });

        return false !== $banned;
    }

    /**
     * Determine the request ip address is in allow countries.
     *
     * @param array $codes
     *
     * @return bool
     */
    public function isAllowCountry(array $codes = ['*'])
    {
        try {
            $isoCode = $this->reader
                ->country($this->ip())
                ->country
                ->isoCode;

            return in_array('*', $codes, true) || in_array($isoCode, $codes, true);
        } catch (\Exception $e) {
            return true;
        }
    }

    /**
     * Ban ip address.
     *
     * @param string|null $ip
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function ban($ip = null)
    {
        session(['isBan' => true]);

        $ip = $ip ?: $this->ip();

        $instance = $this->model
            ->where('ip', $this->encodeIp($ip))
            ->first();

        if (is_null($instance)) {
            $instance = $this->model->create(['ip' => $ip]);
        }

        return $instance;
    }

    /**
     * Unban ip address.
     *
     * @param string|null $ip
     *
     * @return int
     */
    public function unban($ip = null)
    {
        session()->forget('isBan');

        $ip = $ip ?: $this->ip();

        return $this->model->destroy($this->encodeIp($ip));
    }

    /**
     * Unban all ip addresses.
     *
     * @return void
     */
    public function unbanAll()
    {
        $this->model->truncate();
    }

    /**
     * Encode ip address.
     *
     * @param string $ip
     *
     * @return string
     */
    protected function encodeIp($ip)
    {
        return base64_encode(inet_pton($ip));
    }
}
