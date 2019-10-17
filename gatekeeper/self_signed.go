/*
Copyright 2018 All rights reserved.

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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type selfSignedCertificate struct {
	sync.RWMutex
	// certificate holds the current issuing certificate
	certificate tls.Certificate
	// expiration is the certificate expiration
	expiration time.Duration
	// hostnames is the list of host names on the certificate
	hostnames []string
	// privateKey is the rsa private key
	privateKey *rsa.PrivateKey
	// the logger for this service
	log *logrus.Logger
	// stopCh is a channel to close off the rotation
	cancel context.CancelFunc
}

// newSelfSignedCertificate creates and returns a self signed certificate manager
func newSelfSignedCertificate(hostnames []string, expiry time.Duration, log *logrus.Logger) (*selfSignedCertificate, error) {
	if len(hostnames) <= 0 {
		return nil, errors.New("no hostnames specified")
	}
	if expiry < 5*time.Minute {
		return nil, errors.New("expiration must be greater then 5 minutes")
	}

	// @step: generate a certificate pair
	log.WithField("common_name", hostnames[0]).Info("generating a private key for self-signed certificate")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// @step: create an initial certificate
	certificate, err := createCertificate(key, hostnames, expiry)
	if err != nil {
		return nil, err
	}

	// @step: create a context to run under
	ctx, cancel := context.WithCancel(context.Background())

	svc := &selfSignedCertificate{
		certificate: certificate,
		expiration:  expiry,
		hostnames:   hostnames,
		log:         log,
		privateKey:  key,
		cancel:      cancel,
	}

	if err := svc.rotate(ctx); err != nil {
		return nil, err
	}

	return svc, nil
}

// rotate is responsible for rotation the certificate
func (c *selfSignedCertificate) rotate(ctx context.Context) error {
	go func() {
		c.log.WithField("expiration", c.expiration).Info("starting the self-signed certificate rotation")

		for {
			expires := time.Now().Add(c.expiration).Add(-5 * time.Minute)
			ticker := expires.Sub(time.Now())

			select {
			case <-ctx.Done():
				return
			case <-time.After(ticker):
			}
			c.log.WithFields(logrus.Fields{
				"expires":  expires,
				"duration": expires.Sub(time.Now()),
			}).Info("going to sleep until required for rotation")

			// @step: got to sleep until we need to rotate
			time.Sleep(expires.Sub(time.Now()))

			// @step: create a new certificate for us
			cert, _ := createCertificate(c.privateKey, c.hostnames, c.expiration)
			c.log.Info("updating the certificate for server")

			// @step: update the current certificate
			c.updateCertificate(cert)
		}
	}()

	return nil
}

// close is used to shutdown resources
func (c *selfSignedCertificate) close() {
	c.cancel()
}

// updateCertificate is responsible for update the certificate
func (c *selfSignedCertificate) updateCertificate(cert tls.Certificate) {
	c.Lock()
	defer c.Unlock()

	c.certificate = cert
}

// GetCertificate is responsible for retrieving
func (c *selfSignedCertificate) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.RLock()
	defer c.RUnlock()

	return &c.certificate, nil
}
