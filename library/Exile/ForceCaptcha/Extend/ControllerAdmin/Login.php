<?php

class Exile_ForceCaptcha_Extend_ControllerAdmin_Login extends XFCP_Exile_ForceCaptcha_Extend_ControllerAdmin_Login
{
    public function actionLogin()
    {
        if (!$this->_request->isPost())
        {
            return $this->responseRedirect(
                XenForo_ControllerResponse_Redirect::RESOURCE_CANONICAL,
                XenForo_Link::buildAdminLink('index')
            );
        }

        $data = $this->_input->filter(array(
            'login' => XenForo_Input::STRING,
            'password' => XenForo_Input::STRING,
            'redirect' => XenForo_Input::STRING,
            'cookie_check' => XenForo_Input::UINT
        ));

        $redirect = ($data['redirect'] ? $data['redirect'] : XenForo_Link::buildAdminLink('index'));

        $loginModel = $this->_getLoginModel();

        if ($data['cookie_check'] && count($_COOKIE) == 0)
        {
            // login came from a page, so we should at least have a session cookie.
            // if we don't, assume that cookies are disabled
            return $this->responseError(new XenForo_Phrase('cookies_required_to_log_in_to_site'));
        }

        $needCaptcha = $loginModel->requireLoginCaptcha($data['login'], null, null, true);
        if ($needCaptcha)
        {
            // just block logins here instead of using the captcha
            return $this->responseError(new XenForo_Phrase('your_account_has_temporarily_been_locked_due_to_failed_login_attempts'));
        }

        $userModel = $this->_getUserModel();

        $userId = $userModel->validateAuthentication($data['login'], $data['password'], $error);
        if (!$userId)
        {
            $loginModel->logLoginAttempt($data['login']);

            if ($loginModel->requireLoginCaptcha($data['login'], null, null, true))
            {
                return $this->responseError(new XenForo_Phrase('your_account_has_temporarily_been_locked_due_to_failed_login_attempts'));
            }

            if ($this->_input->filterSingle('upgrade', XenForo_Input::UINT))
            {
                return $this->responseRedirect(XenForo_ControllerResponse_Redirect::SUCCESS, $redirect);
            }
            else
            {
                // note - JSON view will return responseError($text)
                return $this->responseView(
                    'XenForo_ViewAdmin_Login_Error',
                    'login_form',
                    array(
                        'text' => $error,
                        'defaultLogin' => $data['login'],
                        'redirect' => $redirect
                    ), array(
                    'containerTemplate' => 'LOGIN_PAGE'
                ));
            }
        }

        $loginModel->clearLoginAttempts($data['login']);

        $user = $this->_getUserModel()->getFullUserById($userId, array(
            'join' => XenForo_Model_User::FETCH_USER_PERMISSIONS
        ));

        // now check that the user will be able to get into the ACP (is_admin)
        if (!$user['is_admin'])
        {
            return $this->responseError(new XenForo_Phrase('your_account_does_not_have_admin_privileges'));
        }

        /** @var XenForo_ControllerHelper_Login $loginHelper */
        $loginHelper = $this->getHelper('Login');

        if ($loginHelper->userTfaConfirmationRequired($user))
        {
            $loginHelper->setTfaSessionCheck($user['user_id']);

            return $this->responseRedirect(
                XenForo_ControllerResponse_Redirect::SUCCESS,
                XenForo_Link::buildAdminLink('login/two-step', null, array(
                    'redirect' => $redirect
                ))
            );
        }
        else
        {
            $permissions = XenForo_Permission::unserializePermissions($user['global_permission_cache']);

            if (empty($user['use_tfa'])
                && XenForo_Application::getConfig()->enableTfa
                && (
                    XenForo_Application::getOptions()->adminRequireTfa
                    || XenForo_Permission::hasPermission($permissions, 'general', 'requireTfa')
                )
            )
            {
                return $this->responseError(new XenForo_Phrase('you_must_enable_two_step_access_control_panel', array(
                    'link' => XenForo_Link::buildPublicLink('account/two-step')
                )));
            }

            $postVars = $this->_input->filterSingle('postVars', XenForo_Input::JSON_ARRAY);
            return $this->completeLogin($userId, $redirect, $postVars);
        }
    }
}