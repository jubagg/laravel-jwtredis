<?php

namespace Sametsahindogan\JWTRedis\Http\Middleware;

use Closure;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;

class PermissionMiddleware extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param $request
     * @param Closure $next
     * @param $permission
     *
     * @return \Illuminate\Http\JsonResponse|mixed
     */
    public function handle($request, Closure $next, $permission)
    {
        try {
            $this->setIfClaimIsNotExist($request);
        } catch (TokenExpiredException | TokenInvalidException | JWTException $e) {
            return $this->getErrorResponse($e);
        }

        $this->setAuthedUser($request);

        $permissions = is_array($permission) ? $permission : explode('|', $permission);

        if (config('jwtredis.check_banned_user')) {
            if (!$request->authedUser->checkUserStatus()) {
                return $this->getErrorResponse('AccountBlockedException');
            }
        }

        foreach ($permissions as $permission) {
            if ($request->authedUser->can($permission)) {
                return $next($request);
            }
        }

        return $this->getErrorResponse('PermissionException');
    }
}
