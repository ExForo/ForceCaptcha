<?php

class Exile_ForceCaptcha_Extend_Model_Login extends XFCP_Exile_ForceCaptcha_Extend_Model_Login
{
    public function requireLoginCaptcha($usernameOrEmail, $maxNoCaptcha = null, $ipAddress = null, $skip = false)
    {
        $response = parent::requireLoginCaptcha($usernameOrEmail, $maxNoCaptcha, $ipAddress);

        if (!$skip)
        {
            return true;
        }

        return $response;
    }
}
