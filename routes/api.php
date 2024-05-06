<?php

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


Route::controller(App\Http\Controllers\Api\UserAuthController::class)->group(function(){

    Route::post('register', 'register');
    Route::post('login', 'login');

});

Route::middleware(['auth:sanctum'])->controller(App\Http\Controllers\Api\UserAuthController::class)->group(function(){
    Route::post('logout', 'logout');
    Route::get('user', 'user');
});
