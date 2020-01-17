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

namespace CCDNUser\SecurityBundle\Component\Listener;

use CCDNUser\SecurityBundle\Component\Authorisation\SecurityManagerInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

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
class BlockingLoginListener
{
    /**
     *
     * @access protected
     * @var \CCDNUser\SecurityBundle\Component\Authorisation\SecurityManagerInterface $securityManager
     */
    protected $securityManager;

    /**
     *
     * @access public
     * @param \CCDNUser\SecurityBundle\Component\Authorisation\SecurityManagerInterface         $securityManager
     */
    public function __construct(SecurityManagerInterface $securityManager)
    {
        $this->securityManager = $securityManager;
    }

    /**
     *
     * If you have failed to login too many times,
     * a log of this will be present in the databse.
     *
     * @access public
     * @param RequestEvent $event
     */
    public function onKernelRequest(RequestEvent $event)
    {
        if ($event->getRequestType() !== \Symfony\Component\HttpKernel\HttpKernel::MASTER_REQUEST) {
            return;
        }

        $securityManager = $this->securityManager; // Avoid the silly cryptic error 'T_PAAMAYIM_NEKUDOTAYIM'
        $result = $securityManager->vote();

        if ($result == $securityManager::ACCESS_ALLOWED) {
            return;
        }

        if ($result == $securityManager::ACCESS_DENIED_BLOCK) {
            $event->stopPropagation();

			throw new AccessDeniedHttpException('flood control - login blocked.');
        }
    }
}
