<?php  namespace LaravelAcl\Authentication\Models;
/**
 * Class Group
 *
 * @author jacopo beschi jacopo@jacopobeschi.com
 */
use Cartalyst\Sentry\Groups\Eloquent\Group as SentryGroup;
use LaravelAcl\Authentication\Models\User;

class Group extends SentryGroup
{
    protected $guarded = ["id"];

    protected $fillable = ["name", "permissions", "protected"];

    public function user()
    {
        return $this->belongsToMany('LaravelAcl\Authentication\Models\User','users_groups','group_id','user_id');
    }


} 