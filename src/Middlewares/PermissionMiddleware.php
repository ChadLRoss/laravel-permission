<?php

namespace Spatie\Permission\Middlewares;

use Closure;
use Illuminate\Support\Facades\Auth;
use Spatie\Permission\Exceptions\UnauthorizedException;

class PermissionMiddleware
{
    public function handle($request, Closure $next, $permission, $tenant = null)
    {
        if (Auth::guest()) {
            throw UnauthorizedException::notLoggedIn();
        }

        $permissions = is_array($permission)
            ? $permission
            : explode('|', $permission);

        foreach ($permissions as $permission) {
            $pass = is_null($tenant) ? Auth::user()->can($permission) : Auth::user()->hasPermissionToTenant($permission, $request->route('tenant'));
            if ($pass) {
                return $next($request);
            }
        }

        throw UnauthorizedException::forPermissions($permissions);
    }
}
