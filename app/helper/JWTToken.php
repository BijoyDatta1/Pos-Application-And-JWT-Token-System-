<?php

namespace App\Helper;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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

}

?>