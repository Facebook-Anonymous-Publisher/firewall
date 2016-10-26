<?php

class FirewallTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var FacebookAnonymousPublisher\Firewall\Firewall
     */
    protected $firewall;

    public function setUp()
    {
        parent::setUp();

        $this->firewall = new FacebookAnonymousPublisher\Firewall\Firewall;
    }

    public function test_ip()
    {
        $_SERVER['HTTP_CF_Connecting_IP'] = '140.109.1.1';

        $_SERVER['REMOTE_ADDR'] = '103.21.244.115';

        $this->assertSame('140.109.1.1', $this->firewall->ip());

        $_SERVER['REMOTE_ADDR'] = '140.109.1.2';

        $this->assertSame('140.109.1.2', $this->firewall->ip());
    }

    public function test_is_banned()
    {
        //
    }

    public function test_is_allow_country()
    {
        $_SERVER['REMOTE_ADDR'] = '140.109.1.1';

        $this->assertTrue($this->firewall->isAllowCountry(['TW']));

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $this->assertTrue($this->firewall->isAllowCountry(['TW']));

        $_SERVER['REMOTE_ADDR'] = '202.232.86.11';

        $this->assertFalse($this->firewall->isAllowCountry(['TW']));
    }

    public function test_ban()
    {
        //
    }

    public function test_unban()
    {
        //
    }
}
