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
     * @var array
     */
    protected $cloudflare = [
        'ipv4' => [
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
        'ipv6' => [
            '2400:cb00::/32',
            '2405:8100::/32',
            '2405:b500::/32',
            '2606:4700::/32',
            '2803:f800::/32',
            '2c0f:f248::/32',
            '2a06:98c0::/29'
        ],
    ];

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
     * Get the IP ranges to be whitelisted.
     *
     * @return array
     */
    protected function whiteList()
    {
        return [
            Whip::CLOUDFLARE_HEADERS => [
                Whip::IPV4 => $this->cloudflare['ipv4'],
                Whip::IPV6 => $this->cloudflare['ipv6'],
            ],
        ];
    }

    /**
     * Get the valid IP address or false if no valid IP address was found.
     *
     * @return false|string
     */
    public function ip()
    {
        return $this->whip->getValidIpAddress();
    }

    /**
     * Determine the request ip is banned or not.
     *
     * @return bool
     */
    public function isBanned()
    {
        $ips = $this->model
            ->all(['ip'])
            ->pluck('ip')
            ->toArray();

        return in_array($this->ip(), $ips, true);
    }

    /**
     * Determine the request ip is in allow countries.
     *
     * @param array $codes
     *
     * @return bool
     */
    public function isAllowCountry($codes = [])
    {
        try {
            $isoCode = $this->reader
                ->country($this->ip())
                ->country
                ->isoCode;
        } catch (\Exception $e) {
            return true;
        }

        return in_array($isoCode, $codes, true);
    }

    /**
     * Ban an ip address.
     *
     * @param null|string $ip
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function ban($ip = null)
    {
        if (is_null($ip)) {
            $ip = $this->ip();
        }

        return $this->model->firstOrCreate(['ip' => $ip]);
    }

    /**
     * Unban an ip address.
     *
     * @param null|string $ip
     *
     * @return int
     */
    public function unban($ip = null)
    {
        if (is_null($ip)) {
            $ip = $this->ip();
        }

        return $this->model->destroy($ip);
    }
}
