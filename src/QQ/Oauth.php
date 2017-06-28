<?php

namespace QQ;

use QQ\Lib\URL;
use QQ\Lib\ErrorCase;


class Oauth{

    const GET_AUTH_CODE_URL = "https://graph.qq.com/oauth2.0/authorize";
    const GET_ACCESS_TOKEN_URL = "https://graph.qq.com/oauth2.0/token";
    const GET_OPENID_URL = "https://graph.qq.com/oauth2.0/me";

    public $urlUtils;
    public $error;
    

    function __construct(){
        $this->urlUtils = new URL();
        $this->error = new ErrorCase();
    }

    public function qq_login($AppId,$Callback,$Scope,$State){

        //-------构造请求参数列表
        $keysArr = array(
            "response_type" => "code",
            "client_id" => $AppId,
            "redirect_uri" => $Callback,
            "state" => $State,
            "scope" => $Scope
        );

        $login_url =  $this->urlUtils->combineURL(self::GET_AUTH_CODE_URL, $keysArr);

        header("Location:$login_url");
    }

    /*
     * $callBackState 回调回来的state $_GET['state'];
     *
     */
    public function qq_callback($AppId,$Callback,$AppKey,$CallBackState,$Code,$State){

        //--------验证state防止CSRF攻击
        if($CallBackState != $State){
            $this->error->showError("30001");
        }

        //-------请求参数列表
        $keysArr = array(
            "grant_type" => "authorization_code",
            "client_id" => $AppId,
            "redirect_uri" => urlencode($Callback),
            "client_secret" => $AppKey,
            "code" => $Code
        );

        //构造请求access_token的url
        $token_url = $this->urlUtils->combineURL(self::GET_ACCESS_TOKEN_URL, $keysArr);
        //发出GET请求
        $response = $this->urlUtils->get_contents($token_url);

        if(strpos($response, "callback") !== false){
            $lpos = strpos($response, "(");
            $rpos = strrpos($response, ")");
            $response  = substr($response, $lpos + 1, $rpos - $lpos -1);
            $msg = json_decode($response);

            if(isset($msg->error)){
                $this->error->showError($msg->error, $msg->error_description);
            }
        }

        $params = array();
        parse_str($response, $params);

        return $params;
    }

    public function get_openid($access_token){

        //-------请求参数列表
        $keysArr = array(
            "access_token" => $access_token
        );

        $graph_url = $this->urlUtils->combineURL(self::GET_OPENID_URL, $keysArr);
        $response = $this->urlUtils->get_contents($graph_url);

        //--------检测错误是否发生
        if(strpos($response, "callback") !== false){
            $lpos = strpos($response, "(");
            $rpos = strrpos($response, ")");
            $response = substr($response, $lpos + 1, $rpos - $lpos -1);
        }

        $user = json_decode($response);
        if(isset($user->error)){
            $this->error->showError($user->error, $user->error_description);
        }

        return $user->openid;

    }
}
