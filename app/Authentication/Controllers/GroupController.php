<?php  namespace LaravelAcl\Authentication\Controllers;
/**
 * Class GroupController
 *
 * @author jacopo beschi jacopo@jacopobeschi.com
 */
use Illuminate\Http\Request;
use Illuminate\Support\MessageBag;
use Illuminate\Support\Facades\Input;
use LaravelAcl\Authentication\Presenters\GroupPresenter;
use LaravelAcl\Library\Form\FormModel;
use LaravelAcl\Authentication\Helpers\FormHelper;
use LaravelAcl\Authentication\Models\Group;
use LaravelAcl\Authentication\Models\User;
use LaravelAcl\Authentication\Exceptions\UserNotFoundException;
use LaravelAcl\Authentication\Validators\GroupValidator;
use LaravelAcl\Library\Exceptions\JacopoExceptionsInterface;
use View, Redirect, App, Config;
use Log;


class GroupController extends Controller
{
    /**
     * @var \LaravelAcl\Authentication\Repository\SentryGroupRepository
     */
    protected $group_repository;
    /**
     * @var \LaravelAcl\Authentication\Validators\GroupValidator
     */
    protected $group_validator;
    /**
     * @var FormHelper
     */
    protected $form_model;

    public function __construct(GroupValidator $v, FormHelper $fh)
    {
        $this->group_repository = App::make('group_repository');
        $this->group_validator = $v;
        $this->f = new FormModel($this->group_validator, $this->group_repository);
        $this->form_model = $fh;
    }

    public function getList(Request $request)
    {
        $groups = $this->group_repository->all($request->all());

        return View::make('laravel-authentication-acl::admin.group.list')->with(["groups" => $groups, "request" => $request]);
    }

    public function editGroup(Request $request)
    {
        try
        {
            $obj = $this->group_repository->find($request->get('id'));
        }
        catch(UserNotFoundException $e)
        {
            $obj = new Group;
        }
        $presenter = new GroupPresenter($obj);

        if($request->get('id') == null)
        {
            return View::make('laravel-authentication-acl::admin.group.edit')->with(["group" => $obj, "presenter" => $presenter]);
        }
        else
            {
                $groupmem = Group::find($request->get('id'));
                $members = $groupmem->user()->get();
                $users = User::all();
                return View::make('laravel-authentication-acl::admin.group.edit')->with(["group" => $obj, "presenter" => $presenter,"users" => $users,"groupmem" => $members,"groupinfo" => $groupmem]);
            }
    }

    public function postEditGroup(Request $request)
    {
            $id = $request->get('id');
            $user_id = $request->get('user_id');
            try
            {
                $obj = $this->f->process($request->all());
                $userObject = User::find($user_id);
                //Adding owner_id to group created
                $obj->owner_id = $userObject->id;
                $obj->save();
                //Updating pivot table and adding group owner association with group created
                $userObject->group()->attach($obj->id);
                $userObject->save();
                Log::info('Group Object');
                Log::info($obj);
                Log::info('User Object');
                Log::info($userObject);
                Log::info('Request Object');
                Log::info($request->all());

            }
            catch(JacopoExceptionsInterface $e)
            {
                $errors = $this->f->getErrors();
                // passing the id incase fails editing an already existing item
                return Redirect::route("groups.edit", $id ? ["id" => $id]: [])->withInput()->withErrors($errors);
            }
            return Redirect::route('groups.edit',["id" => $obj->id])->withMessage(Config::get('acl_messages.flash.success.group_edit_success'));
    }

    public function deleteGroup(Request $request)
    {
        try
        {
            $this->f->delete($request->all());
        }
        catch(JacopoExceptionsInterface $e)
        {
            $errors = $this->f->getErrors();
            return Redirect::route('groups.list')->withErrors($errors);
        }
        return Redirect::route('groups.list')->withMessage(Config::get('acl_messages.flash.success.group_delete_success'));
    }

    public function editPermission(Request $request)
    {
        // prepare input
        $input = $request->all();
        $operation = $request->get('operation');
        $this->form_model->prepareSentryPermissionInput($input, $operation);
        $id = $request->get('id');

        try
        {
            $obj = $this->group_repository->update($id, $input);
        }
        catch(JacopoExceptionsInterface $e)
        {
            return Redirect::route("users.groups.edit")->withInput()->withErrors(new MessageBag(["permissions" => Config::get('acl_messages.flash.error.group_permission_not_found')]));
        }
        return Redirect::route('groups.edit',["id" => $obj->id])->withMessage(Config::get('acl_messages.flash.success.group_permission_edit_success'));
    }

    public function editmembers(Request $request)
    {
        //$input = $request->all();
        //$input1 = Input::get('current_members');
        $id = $request->get('id');
        $input2 = $request->get('current_members');
        $input3 = $request->get('all_users');

        //$alldata = $request->get('all_users')->all();
        //Log::info($alldata);

        //Log::info($id);
        Log::info($input2);
        Log::info($input3);

        if($input2 != null)
        {
            foreach($input2 as $data){
                $user = User::find($data);
                //Log::info($user);
                $user->group()->attach($id);
                $user->save();
            }

        }

        if($input3 != null)
        {
            foreach($input3 as $data){
                $user = User::find($data);
                Log::info($user);
                $user->group()->detach($id);
                $user->save();
            }
        }

        return Redirect::route('groups.list');
    }
}
