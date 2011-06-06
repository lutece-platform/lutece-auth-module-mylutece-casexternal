/*
 * Copyright (c) 2002-2011, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.mylutece.modules.casexternal.authentication;

//import edu.yale.its.tp.cas.client.filter.CASFilter;
import fr.paris.lutece.plugins.mylutece.authentication.ExternalAuthentication;
import fr.paris.lutece.plugins.mylutece.modules.casexternal.service.CASExternalPlugin;
import fr.paris.lutece.portal.service.security.LoginRedirectException;

import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import org.jasig.cas.client.authentication.AttributePrincipal;

import java.util.Iterator;
import java.util.Map;

import javax.security.auth.login.LoginException;

import javax.servlet.http.HttpServletRequest;


/**
 * The class provides an implementation of the inherited abstract class
 * PortalAuthentication based on CAS
 *
 */
public class CASExternalAuthentication extends ExternalAuthentication
{
    // //////////////////////////////////////////////////////////////////////////////////////////////
    // Constants
    private static final String PROPERTY_AUTH_SERVICE_NAME = AppPropertiesService.getProperty( "mylutece-casexternal.service.name" );
    private static final String PROPERTY_DEFAULT_ROLE_NAME = AppPropertiesService.getProperty( "mylutece-casexternal.role.name" );
    private static final String PROPERTY_USER_DIRECTION = "mylutece-casexternal.user.direction";
    private static final String PROPERTY_USER_ROLE = "mylutece-casexternal.user.role";

    /**
     * Constructor
     */
    public CASExternalAuthentication(  )
    {
        super(  );
    }

    /**
     * Gets the Authentication service name
     *
     * @return The name of the authentication service
     */
    public String getAuthServiceName(  )
    {
        return PROPERTY_AUTH_SERVICE_NAME;
    }

    /**
     * Gets the Authentication type
     *
     * @param request
     *            The HTTP request
     * @return The type of authentication
     */
    public String getAuthType( HttpServletRequest request )
    {
        return HttpServletRequest.BASIC_AUTH;
    }

    /**
     * This methods logout the user
     *
     * @param user
     *            The user
     */
    public void logout( LuteceUser user )
    {
    }

    /**
     * 
     *{@inheritDoc}
     */
    public String[] getRolesByUser( LuteceUser user )
    {
        return null;
    }

    /**
     * This method returns an anonymous Lutece user
     *
     * @return An anonymous Lutece user
     */
    public LuteceUser getAnonymousUser(  )
    {
        return new CASExternalUser( LuteceUser.ANONYMOUS_USERNAME, this );
    }

    /**
     * 
     *{@inheritDoc}
     */
    public LuteceUser getHttpAuthenticatedUser(HttpServletRequest request) {

        String strCASExternalUserLogin = request.getRemoteUser();
        AppLogService.debug("You are succesfully logged in as user "	+ request.getRemoteUser());
        CASExternalUser user = null;
        String strUserDir;
        String strUserRole;

        if ( strCASExternalUserLogin != null )
        {
            user = new CASExternalUser( strCASExternalUserLogin, this );
        }

	AttributePrincipal principal = (AttributePrincipal) request.getUserPrincipal();
	Map attributes = principal.getAttributes();

	if (attributes.size() > 0) {

		AppLogService.debug("You have " + attributes.size() + " attributes : ");
		Iterator keyIterator = attributes.keySet().iterator();

		while (keyIterator.hasNext()) {

			String strKey = keyIterator.next().toString();
			String strValue = attributes.get(strKey).toString();
                        user.setUserInfo(strKey, strValue);
			AppLogService.debug("key : '" + strKey + "' / value : '" + strValue + "'");
		}

                //TODO
                //bouchon à supprimer lorsque la direction et la notion de management sera dans l'IAM
                strUserDir = AppPropertiesService.getProperty( PROPERTY_USER_DIRECTION );
                strUserRole = AppPropertiesService.getProperty( PROPERTY_USER_ROLE );

                user.setUserInfo("direction", strUserDir);
                AppLogService.debug("direction : '" + strUserDir + "'");
                user.setUserInfo("role", strUserRole);
                AppLogService.debug("role : '" + strUserRole + "'");

	} 
        else
        {
		AppLogService.debug("You have no attributes set");
	}

        return user;
    }

    /**
     * 
     *{@inheritDoc}
     */
    public LuteceUser login(String string, String string1, HttpServletRequest hsr) throws LoginException, LoginRedirectException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * 
     *{@inheritDoc}
     */
    public boolean isUserInRole(LuteceUser lu, HttpServletRequest hsr, String string) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * 
     *{@inheritDoc}
     */
	public String getName()
	{
		return CASExternalPlugin.PLUGIN_NAME;
	}

	/**
	 * 
	 *{@inheritDoc}
	 */
	public String getPluginName()
	{
		return CASExternalPlugin.PLUGIN_NAME;
	}
}
