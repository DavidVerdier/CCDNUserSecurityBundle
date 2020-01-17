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

namespace CCDNUser\SecurityBundle\Component\Authorisation;

use Symfony\Component\HttpFoundation\RequestStack;
use CCDNUser\SecurityBundle\Component\Authentication\Tracker\LoginFailureTracker;

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
class SecurityManager implements SecurityManagerInterface
{
    /**
     * @var RequestStack
     */
    protected $requestStack;

    /**
     * @var LoginFailureTracker
     */
    protected $loginFailureTracker;

    /**
     *
     * @access protected
     * @var array $routeLogin
     */
    protected $routeLogin;

    /**
     *
     * @access protected
     * @var array $blockPages
     */
    protected $blockPages;

    /**
     * SecurityManager constructor.
     * @param RequestStack $requestStack
     * @param LoginFailureTracker $loginFailureTracker
     * @param $routeLogin
     * @param $blockPages
     */
    public function __construct(RequestStack $requestStack, LoginFailureTracker $loginFailureTracker, $routeLogin, $blockPages)
    {
        $this->requestStack = $requestStack;
        $this->loginFailureTracker = $loginFailureTracker;
        $this->routeLogin = $routeLogin;
        $this->blockPages = $blockPages;
    }

    /**
     * If you have failed to login too many times, a log of this will be present
     * in your session and the databse (incase session is dropped the record remains).
     * 
     * @return int
     * @throws \Exception
     */
    public function vote()
    {
        $request = $this->requestStack->getMasterRequest();
        if ($request) {
            $route = $request->get('_route');
            $ipAddress = $request->getClientIp();

            $this->blockPages['routes'][] = $this->routeLogin['name'];
            if (in_array($route, $this->blockPages['routes'])) {
                // Get number of failed login attempts.
                $attempts = $this->loginFailureTracker->getAttempts($ipAddress, $this->blockPages['duration_in_minutes']);

                if (count($attempts) >= $this->blockPages['after_attempts']) {
                    // You have too many failed login attempts, login access is temporarily blocked.
                    return self::ACCESS_DENIED_BLOCK;
                }
            }
        }

        return self::ACCESS_ALLOWED;
    }
}
