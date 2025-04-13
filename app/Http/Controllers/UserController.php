<?php

namespace App\Http\Controllers;

use App\Helper\JWTToken;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
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

    }

    // otp verification
    public function otpVerification(Request $request){

    }

    //reset password
    public function resetPassword(Request $request){

    }
}
