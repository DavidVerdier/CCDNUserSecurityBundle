<?php

/*
 * This file is part of the CCDNUser SecurityBundle
 *
 * (c) CCDN (c) CodeConsortium <http://www.codeconsortium.com/>
 *
 * Available on github <http://www.github.com/codeconsortium/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace CCDNUser\SecurityBundle\Component\Authentication\Handler;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\Request;
use CCDNUser\SecurityBundle\Component\Authentication\Tracker\LoginFailureTracker;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationFailureHandler;

/**
 *
 * @category CCDNUser
 * @package  SecurityBundle
 *
 * @author   Reece Fowell <reece@codeconsortium.com>
 * @license  http://opensource.org/licenses/MIT MIT
 * @version  Release: 2.0
 * @link     https://github.com/codeconsortium/CCDNUserSecurityBundle
 *
 */
class LoginFailureHandler extends DefaultAuthenticationFailureHandler
{
    /**
     * @var LoginFailureTracker $loginFailureTracker
     */
    protected $loginFailureTracker;

    /**
     * @param LoginFailureTracker $loginFailureTracker
     */
    public function setLoginFailureTracker(LoginFailureTracker $loginFailureTracker)
    {
        $this->loginFailureTracker = $loginFailureTracker;
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     * @return Response
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        // Get the visitors IP address and attempted username.
        $ipAddress = $request->getClientIp();
        if ($request->request->has('_username')) {
            $username = $request->request->get('_username');
        } else {
            $username = '';
        }

        // Make a note of the failed login.
        $this->loginFailureTracker->addAttempt($ipAddress, $username);

        // Let Symfony decide what to do next
        return parent::onAuthenticationFailure($request, $exception);
    }
}
