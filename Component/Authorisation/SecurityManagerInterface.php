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

interface SecurityManagerInterface
{
    const ACCESS_ALLOWED = 0;
    const ACCESS_DENIED_BLOCK = 1;

    /**
     * SecurityManagerInterface constructor.
     * @param RequestStack $requestStack
     * @param LoginFailureTracker $loginFailureTracker
     * @param $routeLogin
     * @param $blockPages
     */
    public function __construct(RequestStack $requestStack, LoginFailureTracker $loginFailureTracker, $routeLogin, $blockPages);

    /**
     * @access public
     * @return int
     */
    public function vote();
}
