<?php

namespace FacebookAnonymousPublisher\Firewall\Models;

use Illuminate\Database\Eloquent\Model;

class Firewall extends Model
{
    /**
     * The primary key for the model.
     *
     * @var string
     */
    protected $primaryKey = 'ip';

    /**
     * The "type" of the auto-incrementing ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = ['ip'];

    /**
     * Get the ip address.
     *
     * @param string $value
     *
     * @return string
     */
    public function getIpAttribute($value)
    {
        return inet_ntop(base64_decode($value, true));
    }

    /**
     * Set the ip address.
     *
     * @param string $value
     *
     * @return void
     */
    public function setIpAttribute($value)
    {
        $this->attributes['ip'] = base64_encode(inet_pton($value));
    }
}
