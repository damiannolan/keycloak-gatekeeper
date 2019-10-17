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
	"net/url"

	"github.com/gambol99/go-oidc/jose"
)

// createStorage creates the store client for use
func createStorage(location string) (storage, error) {
	var store storage
	var err error

	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "redis":
		store, err = newRedisStore(u)
	case "boltdb":
		store, err = newBoltDBStore(u)
	default:
		return nil, fmt.Errorf("unsupport store: %s", u.Scheme)
	}

	return store, err
}

// useStore checks if we are using a store to hold the refresh tokens
func (r *OAuthProxy) useStore() bool {
	return r.store != nil
}

// StoreRefreshToken the token to the store
func (r *OAuthProxy) StoreRefreshToken(token jose.JWT, value string) error {
	return r.store.Set(getHashKey(&token), value)
}

// GetRefreshToken retrieves a token from the store, the key we are using here is the access token
func (r *OAuthProxy) GetRefreshToken(token jose.JWT) (string, error) {
	// step: the key is the access token
	v, err := r.store.Get(getHashKey(&token))
	if err != nil {
		return v, err
	}
	if v == "" {
		return v, ErrNoSessionStateFound
	}

	return v, nil
}

// DeleteRefreshToken removes a key from the store
func (r *OAuthProxy) DeleteRefreshToken(token jose.JWT) error {
	if err := r.store.Delete(getHashKey(&token)); err != nil {
		r.log.WithError(err).Error("unable to delete token")

		return err
	}

	return nil
}

// CloseStore is used to close off any resources
func (r *OAuthProxy) CloseStore() error {
	if r.store != nil {
		return r.store.Close()
	}

	return nil
}
