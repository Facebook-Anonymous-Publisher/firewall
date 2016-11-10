<?php

class FirewallTest extends Base
{
    /**
     * @var FacebookAnonymousPublisher\Firewall\Firewall
     */
    protected $firewall;

    /**
     * @var FacebookAnonymousPublisher\Firewall\Models\Firewall
     */
    protected $model;

    public function setUp()
    {
        parent::setUp();

        $this->firewall = new FacebookAnonymousPublisher\Firewall\Firewall;

        $this->model = new FacebookAnonymousPublisher\Firewall\Models\Firewall;
    }

    public function test_ip()
    {
        $_SERVER['HTTP_CF_Connecting_IP'] = '140.109.1.1';

        $_SERVER['REMOTE_ADDR'] = '103.21.244.115';

        $this->assertSame('140.109.1.1', $this->firewall->ip());

        $_SERVER['REMOTE_ADDR'] = '140.109.1.2';

        $this->assertSame('140.109.1.2', $this->firewall->ip());
    }

    public function test_is_banned_1()
    {
        $this->firewall->ban('140.109.1.1');
        $this->firewall->ban('140.109.1.2');
        $this->firewall->ban('140.109.1.3');

        session()->forget('isBan');

        $_SERVER['REMOTE_ADDR'] = '140.109.1.2';

        $this->assertTrue($this->firewall->isBanned());

        $_SERVER['REMOTE_ADDR'] = '140.109.1.4';

        $this->assertFalse($this->firewall->isBanned());
    }

    public function test_is_banned_2()
    {
        $this->firewall->ban('140.109.1.1');

        $_SERVER['REMOTE_ADDR'] = '140.109.1.2';

        $this->assertTrue($this->firewall->isBanned());

        $_SERVER['REMOTE_ADDR'] = '140.109.1.3';

        $this->assertTrue($this->firewall->isBanned());
    }

    public function test_is_allow_country()
    {
        $this->assertTrue($this->firewall->isAllowCountry());

        $_SERVER['REMOTE_ADDR'] = '140.109.1.1';

        $this->assertTrue($this->firewall->isAllowCountry(['TW']));

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $this->assertTrue($this->firewall->isAllowCountry(['TW']));

        $_SERVER['REMOTE_ADDR'] = '202.232.86.11';

        $this->assertFalse($this->firewall->isAllowCountry(['TW']));
    }

    public function test_ban_and_unban()
    {
        $_SERVER['REMOTE_ADDR'] = '140.109.1.1';

        $this->firewall->ban();

        $this->assertTrue($this->model->where('ip', base64_encode(inet_pton('140.109.1.1')))->exists());

        $this->firewall->ban('140.109.1.2');

        $this->assertTrue($this->model->where('ip', base64_encode(inet_pton('140.109.1.2')))->exists());

        $this->assertCount(2, $this->model->all());

        $this->firewall->unban();

        $this->assertFalse($this->model->where('ip', base64_encode(inet_pton('140.109.1.1')))->exists());

        $this->firewall->unban('140.109.1.2');

        $this->assertFalse($this->model->where('ip', base64_encode(inet_pton('140.109.1.2')))->exists());

        $this->assertCount(0, $this->model->all());
    }

    public function test_unban_all()
    {
        $_SERVER['REMOTE_ADDR'] = '140.109.1.1';

        $this->firewall->ban();
        $this->firewall->ban('140.109.1.2');
        $this->firewall->ban('140.109.1.3');
        $this->firewall->ban('140.109.1.4');
        $this->firewall->ban('140.109.1.5');

        $this->assertCount(5, $this->model->all());

        $this->firewall->unbanAll();

        $this->assertCount(0, $this->model->all());
    }
}
