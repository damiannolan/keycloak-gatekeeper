/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gatekeeper

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gambol99/go-oidc/jose"
	"github.com/gambol99/go-oidc/oidc"
	"github.com/sirupsen/logrus"
)

// proxyMiddleware is responsible for handles reverse proxy request to the upstream endpoint
func (r *OAuthProxy) proxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req)

		// @step: retrieve the request scope
		scope := req.Context().Value(contextScopeName)
		if scope != nil {
			sc := scope.(*RequestScope)
			if sc.AccessDenied {
				return
			}
		}

		// @step: add the proxy forwarding headers
		req.Header.Add("X-Forwarded-For", realIP(req))
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.Header.Get("X-Forwarded-Proto"))

		// @step: add any custom headers to the request
		for k, v := range r.config.Headers {
			req.Header.Set(k, v)
		}

		// @note: by default goproxy only provides a forwarding proxy, thus all requests have to be absolute and we must update the host headers
		req.URL.Host = r.endpoint.Host
		req.URL.Scheme = r.endpoint.Scheme
		if v := req.Header.Get("Host"); v != "" {
			req.Host = v
			req.Header.Del("Host")
		} else if !r.config.PreserveHost {
			req.Host = r.endpoint.Host
		}

		if isUpgradedConnection(req) {
			r.log.WithField("client_ip", req.RemoteAddr).Debug("upgrading the connnection")
			if err := tryUpdateConnection(req, w, r.endpoint); err != nil {
				r.log.WithError(err).Error("failed to upgrade connection")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		r.upstream.ServeHTTP(w, req)
	})
}

// forwardProxyHandler is responsible for signing outbound requests
func (r *OAuthProxy) forwardProxyHandler() func(*http.Request, *http.Response) {
	client, err := r.client.OAuthClient()
	if err != nil {
		r.log.WithError(err).Fatal("failed to create oauth client")
	}
	// the loop state
	var state struct {
		// the access token
		token jose.JWT
		// the refresh token if any
		refresh string
		// the identity of the user
		identity *oidc.Identity
		// the expiry time of the access token
		expiration time.Time
		// whether we need to login
		login bool
		// whether we should wait for expiration
		wait bool
	}
	state.login = true

	// create a routine to refresh the access tokens or login on expiration
	go func() {
		for {
			state.wait = false

			// step: do we have a access token
			if state.login {
				r.log.WithField("username", r.config.ForwardingUsername).Info("requesting access token for user")

				// step: login into the service
				resp, err := client.UserCredsToken(r.config.ForwardingUsername, r.config.ForwardingPassword)
				if err != nil {
					r.log.WithError(err).Error("failed to login to authentication service")
					// step: back-off and reschedule
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: parse the token
				token, identity, err := parseToken(resp.AccessToken)
				if err != nil {
					r.log.WithError(err).Error("failed to parse the access token")
					// step: we should probably hope and reschedule here
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: update the loop state
				state.token = token
				state.identity = identity
				state.expiration = identity.ExpiresAt
				state.wait = true
				state.login = false
				state.refresh = resp.RefreshToken

				r.log.WithFields(logrus.Fields{
					"subject": state.identity.ID,
					"email":   state.identity.Email,
					"expires": state.expiration.Format(time.RFC3339),
				}).Info("successfully retrieved access token for subject")

			} else {
				r.log.WithFields(logrus.Fields{
					"subject": state.identity.ID,
					"email":   state.identity.Email,
				}).Info("access token is about to expiry")

				// step: if we a have a refresh token, we need to login again
				if state.refresh != "" {
					r.log.WithFields(logrus.Fields{
						"subject": state.identity.ID,
						"email":   state.identity.Email,
						"expires": state.expiration.Format(time.RFC3339),
					}).Info("attempting to refresh the access token")

					// step: attempt to refresh the access
					token, expiration, err := getRefreshedToken(r.client, state.refresh)
					if err != nil {
						state.login = true
						switch err {
						case ErrRefreshTokenExpired:
							r.log.WithFields(logrus.Fields{
								"subject": state.identity.ID,
								"email":   state.identity.Email,
							}).Warn("the refresh token has expired, need to login again")
						default:
							r.log.WithError(err).Error("failed to refresh the access token")
						}
						continue
					}

					// step: update the state
					state.token = token
					state.expiration = expiration
					state.wait = true
					state.login = false

					// step: add some debugging
					r.log.WithFields(logrus.Fields{
						"subject": state.identity.ID,
						"email":   state.identity.Email,
						"expires": state.expiration.Format(time.RFC3339),
					}).Info("successfully refreshed the access token")

				} else {
					r.log.WithFields(logrus.Fields{
						"subject": state.identity.ID,
						"email":   state.identity.Email,
					}).Info("session does not support refresh token, acquiring new token")

					// we don't have a refresh token, we must perform a login again
					state.wait = false
					state.login = true
				}
			}

			// wait for an expiration to come close
			if state.wait {
				// set the expiration of the access token within a random 85% of actual expiration
				duration := getWithin(state.expiration, 0.85)
				r.log.WithFields(logrus.Fields{
					"token_expiration": state.expiration.Format(time.RFC3339),
					"renewal_duration": duration.String(),
				}).Info("waiting for expiration of access token")

				<-time.After(duration)
			}
		}
	}()

	return func(req *http.Request, resp *http.Response) {
		hostname := req.Host
		req.URL.Host = hostname
		// is the host being signed?
		if len(r.config.ForwardingDomains) == 0 || containsSubString(hostname, r.config.ForwardingDomains) {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.token.Encode()))
			req.Header.Set("X-Forwarded-Agent", prog)
		}
	}
}
