<?php  namespace LaravelAcl\Authentication\Controllers;

use LaravelAcl\Authentication\Models\User;
use View;

class DashboardController extends Controller{

    public function base()
    {
        $users = User::all();
        $registered = 0;
        $active = 0;
        $pending = 0;
        $banned = 0;
        foreach ($users as $user){
            $registered = $registered + 1;
            if($user->activated == 1)
                $active = $active + 1;
            else
                $pending = $pending + 1;
            if($user->banned == 1)
                $banned = $banned + 1;
        }
        return View::make('laravel-authentication-acl::admin.dashboard.default')->with(["registered_users" => $registered, "active_users" => $active, "pending_users" => $pending, "banned_users" => $banned]);
    }
} 