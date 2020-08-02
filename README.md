# Laravel Sign in with Apple

**Integrate sign in with apple easily**

This package provides an easy sign in with apple authentication model based on the apple specification

- [Laravel Sign in with Apple](#laravel-sign-in-with-apple)
  - [Installation](#installation)
  - [Usage](#usage)
  - [License](#license)

## Installation

Require this package with composer using the following command:

```bash
composer require rinordreshaj/apple-sign-in
```

provide package name & service name generated from on the itunes connect on the .env file

```bash
APPLE_SIGN_IN_PACKAGE_NAME=your.package.name
APPLE_SIGN_IN_SERVICE_NAME=your.service.name
```

## Usage

```php
<?php

namespace App\Http\Controllers\API\Auth;

use Rinordreshaj\AppleSignIn\AppleSignIn;

class AppleSignInController extends Controller
{
    public function login()
    {
        if(AppleSignIn::verify_signature($request->jwt_token))
        {
            // Authentication verified
            $claims = AppleSignIn::parse_user($request->jwt_token);

            $user = User::where([
                        'apple_identity_token' => $claims->apple_identity_token
                    ])->orWhere(["email" => $claims->email])->first();

            if(! $user)
            {
                 // ADD user on database if it doesn't exists
                 $user = User::create($claims->only('apple_identity_token', 'email', 'name', 'username', 'register_source'));
            }
            

            // You can return the authenticated user object 
        }
    }
}
```

## License

The Laravel Sign in with Apple is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT)
