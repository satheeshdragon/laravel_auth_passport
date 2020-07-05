<?php
namespace App\Http\Controllers\API;
 
use App\User; 
use Validator;
use Illuminate\Http\Request; 
use App\Http\Controllers\Controller; 
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth; 
use Symfony\Component\HttpFoundation\Response;
use Laravel\Passport\Client as OClient;

use Exception;
use GuzzleHttp\Client;
 
 
class AuthController extends Controller 
{
  public $successStatus = 200;

 //  public function login(Request $request){ 
 
 //    $credentials = [
 //        'email' => $request->email, 
 //        'password' => $request->password
 //    ];
 
 //    if( auth()->attempt($credentials) ){ 
 //      $user = Auth::user(); 
 //   $success['token'] =  $user->createToken('AppName')->accessToken; 
 //      return response()->json(['success' => $success], 200);
 //    } else { 
 // return response()->json(['error'=>'Unauthorised'], 401);
 //    } 
 //  }
    
 //  public function register(Request $request) 
 //  { 
 //    $validator = Validator::make($request->all(), [ 
 //      'name' => 'required', 
 //      'email' => 'required|email', 
 //      'password' => 'required', 
 //      'password_confirmation' => 'required|same:password', 
 //    ]);
 
 //    if ($validator->fails()) { 
 //      return response()->json([ 'error'=> $validator->errors() ]);
 //    }
 
 // $data = $request->all(); 
 
 // $data['password'] = Hash::make($data['password']);
 
 // $user = User::create($data); 
 // $success['token'] =  $user->createToken('AppName')->accessToken;
 
 // return response()->json(['success'=>$success], 200);
 
 //  }
    
  public function user_detail() 
  { 
 $user = Auth::user();
 return response()->json(['success' => $user], 200); 
  } 


  /* --------------------------------------- */

    public function login() { 
        if (Auth::attempt(['email' => request('email'), 'password' => request('password')])) { 
            $oClient = OClient::where('password_client', 1)->first();
            return $this->getTokenAndRefreshToken($oClient, request('email'), request('password'));
        } 
        else { 
            return response()->json(['error'=>'Unauthorised'], 401); 
        } 
    }

    public function register(Request $request) { 
        $validator = Validator::make($request->all(), [ 
            'name' => 'required', 
            'email' => 'required|email|unique:users', 
            'password' => 'required', 
        ]);

        if ($validator->fails()) { 
            return response()->json(['error'=>$validator->errors()], 401);            
        }

        $password = $request->password;
        $input = $request->all(); 
        $input['password'] = bcrypt($input['password']); 
        $user = User::create($input); 
        $oClient = OClient::where('password_client', 1)->first();
        return $this->getTokenAndRefreshToken($oClient, $user->email, $password);
    }

    public function getTokenAndRefreshToken(OClient $oClient, $email, $password) { 
        $oClient = OClient::where('password_client', 1)->first();
        $http = new Client;
        $response = $http->request('POST', 'localhost/Laravel/laravel_sd/public/oauth/token', [
            'form_params' => [
                'grant_type' => 'password',
                'client_id' => $oClient->id,
                'client_secret' => $oClient->secret,
                'username' => $email,
                'password' => $password,
                'scope' => '*',
            ],
        ]);

        $result = json_decode((string) $response->getBody(), true);
        return response()->json($result, $this->successStatus);
    }
 
}
?>