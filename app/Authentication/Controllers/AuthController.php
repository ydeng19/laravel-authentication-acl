<?php namespace LaravelAcl\Authentication\Controllers;

use Illuminate\Http\Request;
use Sentry, Redirect, App, Config,View;
use LaravelAcl\Authentication\Validators\ReminderValidator;
use LaravelAcl\Library\Exceptions\JacopoExceptionsInterface;
use LaravelAcl\Authentication\Services\ReminderService;
use Regulus\ActivityLog\Activity;


class AuthController extends Controller {

    protected $authenticator;
    protected $reminder;
    protected $reminder_validator;

    public function __construct(ReminderService $reminder, ReminderValidator $reminder_validator)
    {
        $this->authenticator = App::make('authenticator');
        $this->reminder = $reminder;
        $this->reminder_validator = $reminder_validator;
    }

    public function getClientLogin()
    {
//        return view('laravel-authentication-acl::client.auth.login');
        //return View::make('laravel-authentication-acl::client.auth.login');
        \Cas::authenticate();

        // The following codes will not be run, since the login process is superseded by CAS.
        $user = \Cas::getCurrentUser();

        // connect
        $ds = ldap_connect("10.2.11.94", 389) or die("Could not connect to LDAP server.");
        ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

        if ($ds) {

            ldap_bind($ds, "cn=admin,dc=vlab,dc=asu,dc=edu", "CloudServer");

            $result = ldap_search($ds, "ou=Users,dc=vlab,dc=asu,dc=edu", "(mail=$user)") or die ("Error in search query: " . ldap_error($ds));
            $data = ldap_get_entries($ds, $result);
        }
        ldap_close($ds);
        $password = $data[0]["userpassword"][0];


        try
        {
            $this->authenticator->authenticate(array(
                "email" => $user,
                "password" => $password,
            ), true);


//            Activity::log(['contentType' => 'User',
//                'action' => 'Log In',
//                'description' => 'User login',
//                'details' => 'User '.\Cas::getCurrentUser().' logged in from CAS.',
//                'userEmail' => \Cas::getCurrentUser()
//            ]);
        }
        catch(JacopoExceptionsInterface $e)
        {
            $errors = $this->authenticator->getErrors();
            //return Redirect::action('Jacopo\Authentication\Controllers\AuthController@getClientLogin')->withInput()->withErrors($errors);
            \Cas::logout();
            return View::make('laravel-authentication-acl::client.auth.login-email-activation');

        }



        return Redirect::to('/myworkspace'); //->with('global',\Cas::getCurrentUser());

    }

    public function getAdminLogin()
    {
        return view('laravel-authentication-acl::admin.auth.login');
    }

    public function postAdminLogin(Request $request)
    {
        list($email, $password, $remember) = $this->getLoginInput($request);

        try
        {
            $this->authenticator->authenticate(array(
                                                "email" => $email,
                                                "password" => $password
                                             ), $remember);
        }
        catch(JacopoExceptionsInterface $e)
        {
            $errors = $this->authenticator->getErrors();
            return redirect()->route("user.admin.login")->withInput()->withErrors($errors);
        }

        return Redirect::to(Config::get('acl_base.admin_login_redirect_url'));
    }

    public function postClientLogin(Request $request)
    {
        list($email, $password, $remember) = $this->getLoginInput($request);

        try
        {
            $this->authenticator->authenticate(array(
                                                    "email" => $email,
                                                    "password" => $password
                                               ), $remember);
        }
        catch(JacopoExceptionsInterface $e)
        {
            $errors = $this->authenticator->getErrors();
            return redirect()->route("user.login")->withInput()->withErrors($errors);
        }

        return Redirect::to(Config::get('acl_base.user_login_redirect_url'));
    }

    /**
     * Logout utente
     * 
     * @return string
     */
    public function getLogout()
    {
        $this->cloudRes->suspendVMs();
        $this->authenticator->logout();
        if (\Cas::isAuthenticated()) {
//            Activity::log(['contentType' => 'User',
//                'action' => 'Log Out',
//                'description' => 'User logout',
//                'details' => 'User ' . \Cas::getCurrentUser() . ' logged out.',
//                'userEmail' => \Cas::getCurrentUser()
//            ]);
        }
        \Cas::logout();
        return redirect('/');
    }

    /**
     * Recupero password
     */
    public function getReminder()
    {
        return view("laravel-authentication-acl::client.auth.reminder");
    }

    /**
     * Invio token per set nuova password via mail
     *
     * @return mixed
     */
    public function postReminder(Request $request)
    {
        $email = $request->get('email');

        try
        {
            $this->reminder->send($email);
            return redirect()->route("user.reminder-success");
        }
        catch(JacopoExceptionsInterface $e)
        {
            $errors = $this->reminder->getErrors();
            return redirect()->route("user.recovery-password")->withErrors($errors);
        }
    }

    public function getChangePassword(Request $request)
    {
        $email = $request->get('email');
        $token = $request->get('token');

        return view("laravel-authentication-acl::client.auth.changepassword", array("email" => $email, "token" => $token) );
    }

    public function postChangePassword(Request $request)
    {
        $email = $request->get('email');
        $token = $request->get('token');
        $password = $request->get('password');

        if (! $this->reminder_validator->validate($request->all()) )
        {
          return redirect()->route("user.change-password")->withErrors($this->reminder_validator->getErrors())->withInput();
        }

        try
        {
            $this->reminder->reset($email, $token, $password);

            $ds = ldap_connect("10.2.11.94",389)or die("Could not connect to LDAP server.");
            ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
            if ($ds) {
                //if connection success
                //bind to LDAP use admin user
                $r = ldap_bind($ds,"cn=admin,dc=vlab,dc=asu,dc=edu","CloudServer");

                //read from input

                $info["userPassword"] = $password;


                //write to LDAP with a new entry name = email
                $r = ldap_modify($ds,"cn=".$email.",ou=Users,dc=vlab,dc=asu,dc=edu",$info);
            }

            //Close connection
            ldap_close($ds);
        }
        catch(JacopoExceptionsInterface $e)
        {
            $errors = $this->reminder->getErrors();
            return redirect()->route("user.change-password")->withErrors($errors);
        }

        return redirect()->route("user.change-password-success");

    }

    public function postChangePassword2()
    {
        $email = Input::get('email');
        $cur_password = Input::get('cur_pass');
        $token = Input::get('token');
        $password = Input::get('new_pass');

//        if (! $this->reminder_validator->validate(Input::all()) )
//        {
//          return Redirect::action("Jacopo\\Authentication\\Controllers\\AuthController@getChangePassword")->withErrors($this->reminder_validator->getErrors())->withInput();
//        }

        try
        {
            $this->reminder->reset($email, $token, $password);
            $ds = ldap_connect("10.2.11.94",389)or die("Could not connect to LDAP server.");
            ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
            if ($ds) {
                //if connection success
                //bind to LDAP use admin user
                $r = ldap_bind($ds,"cn=admin,dc=vlab,dc=asu,dc=edu","CloudServer");

                $r = ldap_compare($ds, "cn=".$email.",ou=Users,dc=vlab,dc=asu,dc=edu", "userPassword", $cur_password);

                if ($r==true) {
                    //read from input
                    $info["userPassword"] = $password;
                    //write to LDAP with a new entry name = email
                    $r = ldap_modify($ds, "cn=" . $email . ",ou=Users,dc=vlab,dc=asu,dc=edu", $info);
                } else {
                    ldap_close($ds);
                    return "update failed: current password wrong";
                }
            }

            //Close connection
            ldap_close($ds);
        }
        catch(JacopoExceptionsInterface $e)
        {
            $errors = $this->reminder->getErrors();
            return Redirect::action("Jacopo\\Authentication\\Controllers\\AuthController@getChangePassword")->withErrors($errors);
        }

        return "update success";//Redirect::to("user/change-password-success");

    }
    /**
     * @return array
     */
    private function getLoginInput(Request $request)
    {
        $email    = $request->get('email');
        $password = $request->get('password');
        $remember = $request->get('remember');

        return array($email, $password, $remember);
    }
}
