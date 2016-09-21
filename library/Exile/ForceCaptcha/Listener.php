<?php

class Exile_ForceCaptcha_Listener
{
    public static function extendLoginController($class, array &$extend)
    {
        $extend[] = 'Exile_ForceCaptcha_Extend_ControllerPublic_Login';
    }
    public static function extendAdminLoginController($class, array &$extend)
    {
        $extend[] = 'Exile_ForceCaptcha_Extend_ControllerAdmin_Login';
    }
    public static function extendLoginModel($class, array &$extend)
    {
        $extend[] = 'Exile_ForceCaptcha_Extend_Model_Login';
    }
}