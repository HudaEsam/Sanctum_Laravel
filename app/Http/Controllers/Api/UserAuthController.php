<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserAuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:8|confirmed',
            ]);

            $validator->setAttributeNames([
                'name' => 'Name',
                'email' => 'Email',
                'password' => 'Password'
            ]);

            if ($validator->fails()) {
                $errors = $validator->errors();

                $errorMessages = [];

                foreach ($errors->all() as $message) {
                    $errorMessages[] = $message;
                }

                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $errorMessages
                ], 422);
            }

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            return response()->json([
                'status' => true,
                'message' => 'User Created Successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken],
            200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function login(Request $request): JsonResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required','min:8'],
        ]);

        try {

            $user = User::where('email',$credentials['email'])->first();

            if(!$user || !Hash::check($credentials['password'],$user->password)){

                return response()->json(['message' => 'Invalid Credentials'], 401);
            }

            if (Auth::attempt($credentials)) {

                $tokenName = 'fundaToken'.rand(111,999);
                $token = $user->createToken($tokenName)->plainTextToken;

                return response()->json([
                        'status' => 200,
                        'message' => 'Login Successful',
                        'access_token' => $token,
                        'token_type' => 'Bearer',
                    ], 200);
            }else{

                return response()->json(['message' => 'Invalid credentials'], 401);
            }

        } catch (\Throwable $th) {

            return response()->json([
                'message' => 'An unexpected error occurred. Please try again later'.$th->getMessage(),
                'status' => 500
            ], 500);
        }
    }

    public function logout()
    {
        $user = User::findOrFail(Auth::id());
        $user->tokens()->delete();

        return response()->json([
            'status' => 200,
            'message' => 'Logged out successfully'
        ], 200);
    }

    public function user()
    {
        if(Auth::check()){

            $user = Auth::user();

            return response()->json([
                'message' => 'User Detail',
                'data' => $user,
            ], 200);
        }
        else
        {
            return response()->json([
                'message' => 'Login to continue'
            ], 200);
        }
    }
}
