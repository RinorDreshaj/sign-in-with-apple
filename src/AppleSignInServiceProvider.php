<?php

namespace Rinordreshaj\AppleSignIn;

use Illuminate\Support\ServiceProvider;

class AppleSignInServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__ . "./../config/apple_sign_in.php" => config_path("apple_sign_in.php")
        ]);
    }

    public function register()
    {
        $this->app->singleton(AppleSignIn::class, function() {
            return new AppleSignIn();
        });
    }
}