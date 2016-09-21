<?php

class Exile_ForceCaptcha_Extend_ControllerPublic_Login extends XFCP_Exile_ForceCaptcha_Extend_ControllerPublic_Login
{
    public function actionIndex()
    {
        $redirect = $this->getDynamicRedirectIfNot(XenForo_Link::buildPublicLink('login'));
        $redirectAlt = $this->getDynamicRedirectIfNot(XenForo_Link::buildPublicLink('register'));
        if ($redirect != $redirectAlt) {
            // matched one of the two, just go to the index
            $redirect = XenForo_Link::buildPublicLink('index');
        }

        if (XenForo_Visitor::getUserId()) {
            return $this->responseRedirect(
                XenForo_ControllerResponse_Redirect::SUCCESS,
                $redirect
            );
        }

        $viewParams = array(
            'redirect' => $redirect,
            'captcha' => XenForo_Captcha_Abstract::createDefault(true)
        );

        return $this->responseView(
            'XenForo_ViewPublic_Login_Login',
            'login',
            $viewParams,
            $this->_getRegistrationContainerParams()
        );
    }

    public function actionPasswordConfirm()
    {
        $redirect = $this->getDynamicRedirectIfNot(XenForo_Link::buildPublicLink('login/password-confirm'));

        $visitor = XenForo_Visitor::getInstance();
        $userId = $visitor->user_id;

        if (!$userId)
        {
            return $this->responseRedirect(XenForo_ControllerResponse_Redirect::SUCCESS, $redirect, '');
        }

        $auth = $this->_getUserModel()->getUserAuthenticationObjectByUserId($userId);
        if (!$auth || !$auth->hasPassword())
        {
            return $this->responseRedirect(XenForo_ControllerResponse_Redirect::SUCCESS, $redirect, '');
        }

        $this->_assertPostOnly();

        $password = $this->_input->filterSingle('password', XenForo_Input::STRING);

        $loginModel = $this->_getLoginModel();

        $needCaptcha = $loginModel->requireLoginCaptcha($visitor->username, null, null, true);
        if ($needCaptcha)
        {
            return $this->responseError(
                new XenForo_Phrase('your_account_has_temporarily_been_locked_due_to_failed_login_attempts')
            );
        }

        if (!$auth->authenticate($userId, $password))
        {
            $loginModel->logLoginAttempt($visitor->username);

            return $this->responseError(new XenForo_Phrase('incorrect_password'));
        }

        $loginModel->clearLoginAttempts($visitor->username);

        XenForo_Application::getSession()->set('passwordConfirm', XenForo_Application::$time);

        return $this->responseRedirect(XenForo_ControllerResponse_Redirect::SUCCESS, $redirect, '');
    }
}