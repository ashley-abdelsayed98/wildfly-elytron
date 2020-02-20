/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.http.external;

import static org.wildfly.security.http.HttpConstants.EXTERNAL_NAME;
import static org.wildfly.security.mechanism._private.ElytronMessages.httpExternal;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.credential.ExternalCredential;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

/**
 * The EXTERNAL authentication mechanism.
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
public class ExternalAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private final CallbackHandler callbackHandler;

    ExternalAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return EXTERNAL_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {

        String remoteUser = request.getRemoteUser();

        if (remoteUser == null || remoteUser.length() == 0) {
            request.noAuthenticationInProgress();
            return;
        }

        IdentityCredentialCallback credentialUpdateCallback = new IdentityCredentialCallback(ExternalCredential.INSTANCE, true);
        try {
            callbackHandler.handle(new Callback[]{credentialUpdateCallback});
            if (authorize(remoteUser)) {
                succeed(request);
            } else {
                fail(request);
            }
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            httpExternal.tracef("Unsupported callback [%s]", credentialUpdateCallback);
        } catch (IOException exception) {
            throw  httpExternal.mechCallbackHandlerFailedForUnknownReason(exception).toHttpAuthenticationException();
        }

    }

    private boolean authorize(String username) throws AuthenticationMechanismException {
        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);

        try {
            callbackHandler.handle(new Callback[] {authorizeCallback});
            return authorizeCallback.isAuthorized();
        } catch (UnsupportedCallbackException e) {
            return false;
        } catch (Throwable t) {
            throw httpExternal.mechCallbackHandlerFailedForUnknownReason(t);
        }
    }

    private void succeed(HttpServerRequest request) throws AuthenticationMechanismException {
        try {
            callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED });
            request.authenticationComplete();
        } catch (Throwable t) {
            throw httpExternal.mechCallbackHandlerFailedForUnknownReason(t);
        }
    }

    private void fail(HttpServerRequest request) throws AuthenticationMechanismException {
        try {
            callbackHandler.handle(new Callback[]{AuthenticationCompleteCallback.FAILED});
            request.authenticationFailed(httpExternal.authenticationFailed());
        } catch (Throwable t) {
            throw httpExternal.mechCallbackHandlerFailedForUnknownReason(t);
        }
    }
}
