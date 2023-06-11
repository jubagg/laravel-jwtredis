<?php

namespace Sametsahindogan\JWTRedis\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;

class Authenticate extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param $request
     * @param Closure $next
     *
     * @return JsonResponse
     */
    public function handle($request, Closure $next)
    {
        try {
            $this->setIfClaimIsNotExist($request);
        } catch (TokenExpiredException | TokenInvalidException | JWTException | TokenBlacklistedException $e) {
            return $this->getErrorResponse($e);
        }

        if (config('jwtredis.check_banned_user')) {
            $this->setAuthedUser($request);

            if (!$request->authedUser->checkUserStatus()) {
                return $this->getErrorResponse('AccountBlockedException');
            }
        }

        return $next($request);
    }
}
