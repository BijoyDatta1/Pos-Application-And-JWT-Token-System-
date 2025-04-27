<?php

namespace App\Http\Controllers;

use App\Helper\JWTToken;
use App\Mail\SendOtpMail;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    //registation user
    public function registration(Request $request){
        $Validation = Validator::make($request->all(),[
            'firstName' => 'required',
            'lastName' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
            'mobile' => 'required'
        ]);
        if($Validation->fails()){
            return response()->json([
                'status' => false,
                'error' => $Validation->messages()
            ], 401);
        }
        $user = User::create([
            'firstName' => $request->firstName,
            'lastName' => $request->lastName,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'mobile' => $request->mobile

        ]);

        return response()->json([
            'status' => true,
            'message' => 'User created successfully',
            'user' => $user
        ],201);
    }

    //login user
    public function login(Request $request){
        $Validation = Validator::make($request->all(),
        [
            'email' => 'required|email',
            'password' => 'required'
        ]);
        if($Validation->fails()){
            return response()->json([
                'status' => false,
                'error' => $Validation->messages()
            ],401);
        }
        $user = User::where('email', $request->email)->first();
        if($user && Hash::check($request->password, $user->password)){
            $token = JWTToken::CreateToken($user->email,$user->id);
            return response()->json([
                'status' => true,
                'message' => 'User logged in successfully',
                'token' => $token,
            ],201);
        }else{
            return response()->json([
                'status' => false,
                'message' => 'Invalid email or password'
            ],401);
        }
    }

    //otp send, otpVerification, Reset Password
    //send otp
    public function sendOtp(Request $request){
        $user = User::where('email',$request->email)->first();
        if($user){
            $otp = rand(10000,99999);
            $send = Mail::to($user->email)->send(new SendOtpMail($otp));

            if($send){
                $user->update([
                    'otp' => $otp
                ]);
                return response()->json([
                    'status' => true,
                    'message' => 'Otp sent successfully',
                    "otp" =>$otp
                ],201);
            }

        }else{
            return response()->json([
                'status' => false,
                'message' => 'User not found'
            ],401);
        }
    }

    // otp verification
    public function otpVerification(Request $request){
        $result = User::where('email',$request->email)->where('otp',$request->otp)->first();
        // return response()->json([
        //     'email' => $result->email
        // ]);
        // die();
        if($result != null){
            $token = JWTToken::CreateToken($result->email,$result->id);
            User::Where('email',$request->email)->Update(['otp' => 0]);
            return response()->json([
                'status' => true,
                "message" => "Otp Verification Successfull",
                'token' => $token
            ],200);
        }else{
            return response()->json([
                'status' =>false,
                'message' => "Otp Verification Faild"
            ],401);
        }
    }

    //reset password
    public function resetPassword(Request $request){
        try{
            //This Header Email Set in TokenVerificationMiddleware Class
            $email = $request->header('email');
            $password = $request->password;
            User::where('email', $email)->update(['password'=> bcrypt($password)]);
            return response()->json([
                'status' => true,
                'message' => 'Password Update Successfull'
            ],200);
        }catch(Exception $e){
            return response()->json([
                'status' => false,
                "message" => "Password Update Faild"
            ],401);
        }
    }
}
