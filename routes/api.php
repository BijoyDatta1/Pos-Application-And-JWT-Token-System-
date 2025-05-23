<?php

use App\Http\Controllers\UserController;
use App\Http\Middleware\TokenVerificationMiddleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::post('/registation', [UserController::class,'registration']);
Route::post('/login', [UserController::class,'login']);
Route::post('/logout', [UserController::class,'logout']);
Route::post('/sendotp', [UserController::class,'sendOtp']);
Route::post('/verifyotp', [UserController::class,'otpVerification']);
Route::post('/resetPassword',[UserController::class,'resetPassword'])->middleware(TokenVerificationMiddleware::class);
