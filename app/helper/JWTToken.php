<?php

namespace App\Helper;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PhpParser\Node\Stmt\TryCatch;

class JWTToken{

    public static function CreateToken($userEmail,$userId):string{
        $key = env('JWT_KEY');
        $payload = [
            'iss' => 'laravel-token',
            'iat' => time(),
            'exp' => time()+60*60,
            'userEmail' => $userEmail,
            'userId' => $userId
        ];
        return JWT::encode($payload,$key,'HS256');
    }

    public static function VerifyToken($token){

            try{
                if($token != null){
                    $key = env('JWT_KEY');
                    $decode = JWT::decode($token, new Key( $key, 'HS256' ));
                    return $decode;
                }else{
                    return "Unauthorize";
                }
            }catch(Exception $e){
                return "Unvalied Token";
            }
    }

}
?>