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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	httplog "log"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/gambol99/go-oidc/oidc"
	"github.com/gambol99/goproxy"
	"github.com/pressly/chi"
	"github.com/pressly/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
)

// OAuthProxy - Bootstrapped Gatekeeper struct
type OAuthProxy struct {
	client         *oidc.Client
	config         *Config
	endpoint       *url.URL
	idp            oidc.ProviderConfig
	idpClient      *http.Client
	listener       net.Listener
	log            *logrus.Logger
	metricsHandler http.Handler
	router         http.Handler
	server         *http.Server
	shutdownCh     chan bool
	store          storage
	templates      *template.Template
	upstream       reverseProxy
}

func init() {
	time.LoadLocation("UTC")             // ensure all time is in UTC
	runtime.GOMAXPROCS(runtime.NumCPU()) // set the core
	prometheus.MustRegister(certificateRotationMetric)
	prometheus.MustRegister(latencyMetric)
	prometheus.MustRegister(oauthLatencyMetric)
	prometheus.MustRegister(oauthTokensMetric)
	prometheus.MustRegister(statusMetric)
}

// NewProxy create's a new proxy from configuration
func NewProxy(config *Config) (*OAuthProxy, error) {
	var err error
	// create the service logger
	log := createLogger(config)

	log.WithFields(logrus.Fields{"app": prog, "tenantID": "TENANTID"}).Info("starting the service")
	svc := &OAuthProxy{
		config:         config,
		log:            log,
		metricsHandler: prometheus.Handler(),
		shutdownCh:     make(chan bool),
	}

	// parse the upstream endpoint
	if svc.endpoint, err = url.Parse(config.Upstream); err != nil {
		return nil, err
	}

	// initialize the store if any
	if config.StoreURL != "" {
		if svc.store, err = createStorage(config.StoreURL); err != nil {
			return nil, err
		}
	}

	// initialize the openid client
	if !config.SkipTokenVerification {
		if svc.client, svc.idp, svc.idpClient, err = svc.newOpenIDClient(); err != nil {
			return nil, err
		}
	} else {
		log.Warn("TESTING ONLY CONFIG - the verification of the token have been disabled")
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		log.Warn("client credentials are not set, depending on provider (confidential|public) you might be unable to auth")
	}

	// are we running in forwarding mode?
	if config.EnableForwarding {
		if err := svc.createForwardingProxy(); err != nil {
			return nil, err
		}
	} else {
		if err := svc.createReverseProxy(); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

// createReverseProxy creates a reverse proxy
func (r *OAuthProxy) createReverseProxy() error {
	r.log.WithFields(logrus.Fields{"url": r.config.Upstream}).Info("enabled reverse proxy mode, upstream url")
	if err := r.createUpstreamProxy(r.endpoint); err != nil {
		return err
	}
	engine := chi.NewRouter()
	engine.MethodNotAllowed(emptyHandler)
	engine.NotFound(emptyHandler)
	engine.Use(middleware.Recoverer)
	// @check if the request tracking id middleware is enabled
	if r.config.EnableRequestID {
		r.log.Info("enabled the correlation request id middlware")
		engine.Use(r.requestIDMiddleware(r.config.RequestIDHeader))
	}
	// @step: enable the entrypoint middleware
	engine.Use(entrypointMiddleware)

	if r.config.EnableLogging {
		engine.Use(r.loggingMiddleware)
	}
	if r.config.EnableSecurityFilter {
		engine.Use(r.securityMiddleware)
	}

	if len(r.config.CorsOrigins) > 0 {
		c := cors.New(cors.Options{
			AllowedOrigins:   r.config.CorsOrigins,
			AllowedMethods:   r.config.CorsMethods,
			AllowedHeaders:   r.config.CorsHeaders,
			AllowCredentials: r.config.CorsCredentials,
			ExposedHeaders:   r.config.CorsExposedHeaders,
			MaxAge:           int(r.config.CorsMaxAge.Seconds()),
		})
		engine.Use(c.Handler)
	}

	engine.Use(r.proxyMiddleware)
	r.router = engine

	if len(r.config.ResponseHeaders) > 0 {
		engine.Use(r.responseHeaderMiddleware(r.config.ResponseHeaders))
	}

	// step: add the routing for oauth
	engine.With(proxyDenyMiddleware).Route(r.config.OAuthURI, func(e chi.Router) {
		e.MethodNotAllowed(methodNotAllowHandlder)
		e.HandleFunc(authorizationURL, r.oauthAuthorizationHandler)
		e.Get(callbackURL, r.oauthCallbackHandler)
		e.Get(expiredURL, r.expirationHandler)
		e.Get(healthURL, r.healthHandler)
		e.Get(logoutURL, r.logoutHandler)
		e.Get(tokenURL, r.tokenHandler)
		e.Post(loginURL, r.loginHandler)
		if r.config.EnableMetrics {
			r.log.WithFields(logrus.Fields{"path": r.config.WithOAuthURI(metricsURL)}).Info("enabled the service metrics middleware")
			e.Get(metricsURL, r.proxyMetricsHandler)
		}
	})

	if r.config.EnableProfiling {
		engine.With(proxyDenyMiddleware).Route(debugURL, func(e chi.Router) {
			r.log.Warn("enabling the debug profiling on /debug/pprof")
			e.Get("/{name}", r.debugHandler)
			e.Post("/{name}", r.debugHandler)
		})
		// @check if the server write-timeout is still set and throw a warning
		if r.config.ServerWriteTimeout > 0 {
			r.log.Warn("you must disable the server write timeout (--server-write-timeout) when using pprof profiling")
		}
	}

	if r.config.EnableSessionCookies {
		r.log.Info("using session cookies only for access and refresh tokens")
	}

	// step: load the templates if any
	if err := r.createTemplates(); err != nil {
		return err
	}
	// step: provision in the protected resources
	enableDefaultDeny := r.config.EnableDefaultDeny
	for _, x := range r.config.Resources {
		if x.URL[len(x.URL)-1:] == "/" {
			r.log.WithFields(logrus.Fields{
				"resource": x.URL,
				"change":   x.URL,
				"amended":  strings.TrimRight(x.URL, "/"),
			}).Warn("the resource url is not a prefix")
		}
		if x.URL == "/*" && r.config.EnableDefaultDeny {
			switch x.WhiteListed {
			case true:
				return errors.New("you've asked for a default denial but whitelisted everything")
			default:
				enableDefaultDeny = false
			}
		}
	}

	if enableDefaultDeny {
		r.log.Info("adding a default denial into the protected resources")
		r.config.Resources = append(r.config.Resources, &Resource{URL: "/*", Methods: allHTTPMethods})
	}

	for _, x := range r.config.Resources {
		r.log.WithFields(logrus.Fields{"resource": x.String()}).Info("protecting resource")
		e := engine.With(
			r.authenticationMiddleware(x),
			r.admissionMiddleware(x),
			r.identityHeadersMiddleware(r.config.AddClaims))

		for _, m := range x.Methods {
			if !x.WhiteListed {
				e.MethodFunc(m, x.URL, emptyHandler)
				continue
			}
			engine.MethodFunc(m, x.URL, emptyHandler)
		}
	}

	for name, value := range r.config.MatchClaims {
		r.log.WithFields(logrus.Fields{"claim": name, "value": value}).Info("token must contain")
	}
	if r.config.RedirectionURL == "" {
		r.log.Warn("no redirection url has been set, will use host headers")
	}
	if r.config.EnableEncryptedToken {
		r.log.Info("session access tokens will be encrypted")
	}

	return nil
}

// createForwardingProxy creates a forwarding proxy
func (r *OAuthProxy) createForwardingProxy() error {
	r.log.WithFields(logrus.Fields{"interface": r.config.Listen}).Info("enabling forward signing mode, listening on")

	if r.config.SkipUpstreamTLSVerify {
		r.log.Warn("tls verification switched off. In forward signing mode it's recommended you verify! (--skip-upstream-tls-verify=false)")
	}
	if err := r.createUpstreamProxy(nil); err != nil {
		return err
	}
	forwardingHandler := r.forwardProxyHandler()

	// set the http handler
	proxy := r.upstream.(*goproxy.ProxyHttpServer)
	r.router = proxy

	// setup the tls configuration
	if r.config.TLSCaCertificate != "" && r.config.TLSCaPrivateKey != "" {
		ca, err := loadCA(r.config.TLSCaCertificate, r.config.TLSCaPrivateKey)
		if err != nil {
			return fmt.Errorf("unable to load certificate authority, error: %s", err)
		}

		// implement the goproxy connect method
		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action:    goproxy.ConnectMitm,
					TLSConfig: goproxy.TLSConfigFromCA(ca),
				}, host
			},
		)
	} else {
		// use the default certificate provided by goproxy
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// @NOTES, somewhat annoying but goproxy hands back a nil response on proxy client errors
		if resp != nil && r.config.EnableLogging {
			start := ctx.UserData.(time.Time)
			latency := time.Since(start)
			latencyMetric.Observe(latency.Seconds())
			r.log.WithFields(logrus.Fields{
				"method":  resp.Request.Method,
				"path":    resp.Request.URL.Path,
				"status":  resp.StatusCode,
				"bytes":   resp.ContentLength,
				"host":    resp.Request.Host,
				"latency": latency.String(),
			}).Info("client request")
		}

		return resp
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		forwardingHandler(req, ctx.Resp)
		return req, ctx.Resp
	})

	return nil
}

// Run starts the proxy service
func (r *OAuthProxy) Run() error {
	listener, err := r.createHTTPListener(listenerConfig{
		ca:                  r.config.TLSCaCertificate,
		certificate:         r.config.TLSCertificate,
		clientCert:          r.config.TLSClientCertificate,
		hostnames:           r.config.Hostnames,
		letsEncryptCacheDir: r.config.LetsEncryptCacheDir,
		listen:              r.config.Listen,
		privateKey:          r.config.TLSPrivateKey,
		proxyProtocol:       r.config.EnableProxyProtocol,
		redirectionURL:      r.config.RedirectionURL,
		useFileTLS:          r.config.TLSPrivateKey != "" && r.config.TLSCertificate != "",
		useLetsEncryptTLS:   r.config.UseLetsEncrypt,
		useSelfSignedTLS:    r.config.EnabledSelfSignedTLS,
	})

	if err != nil {
		return err
	}
	// step: create the http server
	server := &http.Server{
		Addr:         r.config.Listen,
		Handler:      r.router,
		ReadTimeout:  r.config.ServerReadTimeout,
		WriteTimeout: r.config.ServerWriteTimeout,
		IdleTimeout:  r.config.ServerIdleTimeout,
	}
	r.server = server
	r.listener = listener
	r.waitForShutdown()

	go func() {
		r.log.WithFields(logrus.Fields{"interface": r.config.Listen}).Info("keycloak proxy service starting")
		if err = server.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				r.log.WithError(err).Fatal("failed to start the http service")
			}
		}
	}()

	// step: are we running http service as well?
	if r.config.ListenHTTP != "" {
		r.log.WithFields(logrus.Fields{"interface": r.config.Listen}).Info("keycloak proxy http service starting")
		httpListener, err := r.createHTTPListener(listenerConfig{
			listen:        r.config.ListenHTTP,
			proxyProtocol: r.config.EnableProxyProtocol,
		})
		if err != nil {
			return err
		}
		httpsvc := &http.Server{
			Addr:         r.config.ListenHTTP,
			Handler:      r.router,
			ReadTimeout:  r.config.ServerReadTimeout,
			WriteTimeout: r.config.ServerWriteTimeout,
			IdleTimeout:  r.config.ServerIdleTimeout,
		}
		go func() {
			if err := httpsvc.Serve(httpListener); err != nil {
				r.log.WithError(err).Fatal("failed to start the http redirect service")
			}
		}()
	}

	return nil
}

// Addr - Returns the OAuthProxy listener address as a string value
func (r *OAuthProxy) Addr() string {
	return r.listener.Addr().String()
}

// Shutdown - Notifies the OAuthProxy shutdownCh
func (r *OAuthProxy) Shutdown() {
	r.shutdownCh <- true
}

// waitForShutdown - Starts a new goroutine to block until receiving on the OAuthProxy shutdownCh
func (r *OAuthProxy) waitForShutdown() {
	go func() {
		<-r.shutdownCh
		r.log.Info("shutting down keycloak-proxy")
		if err := r.server.Shutdown(context.Background()); err != nil {
			r.log.WithError(err).Error("failed to shutdown keycloak-proxy")
		}
		close(r.shutdownCh)
	}()
}

// listenerConfig encapsulate listener options
type listenerConfig struct {
	ca                  string   // the path to a certificate authority
	certificate         string   // the path to the certificate if any
	clientCert          string   // the path to a client certificate to use for mutual tls
	hostnames           []string // list of hostnames the service will respond to
	letsEncryptCacheDir string   // the path to cache letsencrypt certificates
	listen              string   // the interface to bind the listener to
	privateKey          string   // the path to the private key if any
	proxyProtocol       bool     // whether to enable proxy protocol on the listen
	redirectionURL      string   // url to redirect to
	useFileTLS          bool     // indicates we are using certificates from files
	useLetsEncryptTLS   bool     // indicates we are using letsencrypt
	useSelfSignedTLS    bool     // indicates we are using the self-signed tls
}

// ErrHostNotConfigured indicates the hostname was not configured
var ErrHostNotConfigured = errors.New("acme/autocert: host not configured")

// createHTTPListener is responsible for creating a listening socket
func (r *OAuthProxy) createHTTPListener(config listenerConfig) (net.Listener, error) {
	var listener net.Listener
	var err error

	// are we create a unix socket or tcp listener?
	if strings.HasPrefix(config.listen, "unix://") {
		socket := config.listen[7:]
		if exists := fileExists(socket); exists {
			if err = os.Remove(socket); err != nil {
				return nil, err
			}
		}
		r.log.WithFields(logrus.Fields{"interface": config.listen}).Info("listening on unix socket")
		if listener, err = net.Listen("unix", socket); err != nil {
			return nil, err
		}
	} else {
		if listener, err = net.Listen("tcp", config.listen); err != nil {
			return nil, err
		}
	}

	// does it require proxy protocol?
	if config.proxyProtocol {
		r.log.WithFields(logrus.Fields{"interface": config.listen}).Info("enabling the proxy protocol on listener")
		listener = &proxyproto.Listener{Listener: listener}
	}

	// @check if the socket requires TLS
	if config.useSelfSignedTLS || config.useLetsEncryptTLS || config.useFileTLS {
		getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("Not configured")
		}

		if config.useLetsEncryptTLS {
			r.log.Info("enabling letsencrypt tls support")

			m := autocert.Manager{
				Prompt: autocert.AcceptTOS,
				Cache:  autocert.DirCache(config.letsEncryptCacheDir),
				HostPolicy: func(_ context.Context, host string) error {
					if len(config.hostnames) > 0 {
						found := false

						for _, h := range config.hostnames {
							found = found || (h == host)
						}

						if !found {
							return ErrHostNotConfigured
						}
					} else if config.redirectionURL != "" {
						if u, err := url.Parse(config.redirectionURL); err != nil {
							return err
						} else if u.Host != host {
							return ErrHostNotConfigured
						}
					}

					return nil
				},
			}

			getCertificate = m.GetCertificate
		}

		if config.useSelfSignedTLS {
			r.log.WithFields(logrus.Fields{"expiration": r.config.SelfSignedTLSExpiration}).Info("enabling self-signed tls support")

			rotate, err := newSelfSignedCertificate(r.config.SelfSignedTLSHostnames, r.config.SelfSignedTLSExpiration, r.log)
			if err != nil {
				return nil, err
			}
			getCertificate = rotate.GetCertificate

		}

		if config.useFileTLS {
			r.log.WithFields(logrus.Fields{
				"certificate": config.certificate,
				"private_key": config.privateKey,
			}).Info("tls support enabled")
			rotate, err := newCertificateRotator(config.certificate, config.privateKey, r.log)
			if err != nil {
				return nil, err
			}
			// start watching the files for changes
			if err := rotate.watch(); err != nil {
				return nil, err
			}

			getCertificate = rotate.GetCertificate
		}

		tlsConfig := &tls.Config{
			GetCertificate:           getCertificate,
			PreferServerCipherSuites: true,
		}

		listener = tls.NewListener(listener, tlsConfig)

		// @check if we doing mutual tls
		if config.clientCert != "" {
			caCert, err := ioutil.ReadFile(config.clientCert)
			if err != nil {
				return nil, err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return listener, nil
}

// createUpstreamProxy create a reverse http proxy from the upstream
func (r *OAuthProxy) createUpstreamProxy(upstream *url.URL) error {
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	// are we using a unix socket?
	if upstream != nil && upstream.Scheme == "unix" {
		r.log.WithFields(logrus.Fields{"socket": fmt.Sprintf("%s%s", upstream.Host, upstream.Path)}).Info("using unix socket for upstream")

		socketPath := fmt.Sprintf("%s%s", upstream.Host, upstream.Path)
		dialer = func(network, address string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}
		upstream.Path = ""
		upstream.Host = "domain-sock"
		upstream.Scheme = "http"
	}
	// create the upstream tls configure
	tlsConfig := &tls.Config{InsecureSkipVerify: r.config.SkipUpstreamTLSVerify}

	// are we using a client certificate
	// @TODO provide a means of reload on the client certificate when it expires. I'm not sure if it's just a
	// case of update the http transport settings - Also we to place this go-routine?
	if r.config.TLSClientCertificate != "" {
		cert, err := ioutil.ReadFile(r.config.TLSClientCertificate)
		if err != nil {
			r.log.WithError(err).Error("unable to read client certificate")
			return err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cert)
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	{
		// @check if we have a upstream ca to verify the upstream
		if r.config.UpstreamCA != "" {
			r.log.WithFields(logrus.Fields{"path": r.config.UpstreamCA}).Info("loading the upstream ca")
			ca, err := ioutil.ReadFile(r.config.UpstreamCA)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			tlsConfig.RootCAs = pool
		}
	}

	// create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = httplog.New(ioutil.Discard, "", 0)
	r.upstream = proxy

	// update the tls configuration of the reverse proxy
	r.upstream.(*goproxy.ProxyHttpServer).Tr = &http.Transport{
		Dial:                  dialer,
		DisableKeepAlives:     !r.config.UpstreamKeepalives,
		ExpectContinueTimeout: r.config.UpstreamExpectContinueTimeout,
		ResponseHeaderTimeout: r.config.UpstreamResponseHeaderTimeout,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   r.config.UpstreamTLSHandshakeTimeout,
		MaxIdleConns:          r.config.MaxIdleConns,
		MaxIdleConnsPerHost:   r.config.MaxIdleConnsPerHost,
	}

	return nil
}

// createTemplates loads the custom template
func (r *OAuthProxy) createTemplates() error {
	var list []string

	if r.config.SignInPage != "" {
		r.log.WithFields(logrus.Fields{"page": r.config.SignInPage}).Debug("loading the custom sign in page")
		list = append(list, r.config.SignInPage)
	}

	if r.config.ForbiddenPage != "" {
		r.log.WithFields(logrus.Fields{"page": r.config.ForbiddenPage}).Debug("loading the custom sign forbidden page")
		list = append(list, r.config.ForbiddenPage)
	}

	if len(list) > 0 {
		r.log.WithFields(logrus.Fields{"templates": strings.Join(list, ",")}).Info("loading the custom templates")
		r.templates = template.Must(template.ParseFiles(list...))
	}

	return nil
}

// newOpenIDClient initializes the openID configuration, note: the redirection url is deliberately left blank
// in order to retrieve it from the host header on request
func (r *OAuthProxy) newOpenIDClient() (*oidc.Client, oidc.ProviderConfig, *http.Client, error) {
	var err error
	var config oidc.ProviderConfig

	// step: fix up the url if required, the underlining lib will add the .well-known/openid-configuration to the discovery url for us.
	if strings.HasSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration") {
		r.config.DiscoveryURL = strings.TrimSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration")
	}

	// step: create a idp http client
	hc := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				if r.config.OpenIDProviderProxy != "" {
					idpProxyURL, err := url.Parse(r.config.OpenIDProviderProxy)
					if err != nil {
						r.log.WithError(err).Warn("invalid proxy address for open IDP provider proxy")
						return nil, nil
					}
					return idpProxyURL, nil
				}

				return nil, nil
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: r.config.SkipOpenIDProviderTLSVerify,
			},
		},
		Timeout: time.Second * 10,
	}

	// step: attempt to retrieve the provider configuration
	config, err = r.retrieveProviderConfig(hc)
	if err != nil {
		r.log.Warn("failed to retrieve oidc configuration from provider")
		return nil, config, nil, err
	}

	client, err := oidc.NewClient(oidc.ClientConfig{
		Credentials: oidc.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		HTTPClient:        hc,
		RedirectURL:       fmt.Sprintf("%s/oauth/callback", r.config.RedirectionURL),
		ProviderConfig:    config,
		Scope:             append(r.config.Scopes, oidc.DefaultScope...),
		SkipClientIDCheck: r.config.SkipClientID,
	})
	if err != nil {
		return nil, config, hc, err
	}
	// start the provider sync for key rotation
	client.SyncProviderConfig(r.config.DiscoveryURL)

	return client, config, hc, nil
}

func (r *OAuthProxy) retrieveProviderConfig(hc *http.Client) (oidc.ProviderConfig, error) {
	var config oidc.ProviderConfig
	var err error

	timeout := time.After(r.config.OpenIDProviderTimeout)

FetchLoop:
	for {
		select {
		case <-timeout:
			return config, errors.New("failed to retrieve the provider configuration from discovery url")
		default:
			r.log.WithFields(logrus.Fields{
				"url":     r.config.DiscoveryURL,
				"timeout": r.config.OpenIDProviderTimeout.String(),
			}).Info("attempting to retrieve configuration discovery url")
			if config, err = oidc.FetchProviderConfig(hc, r.config.DiscoveryURL); err == nil {
				r.log.Info("successfully retrieved openid configuration from the discovery")
				break FetchLoop
			}
			r.log.WithError(err).Warn("failed to get provider configuration from discovery")
			time.Sleep(time.Second * 3)
		}
	}

	return config, nil
}

// Render implements the echo Render interface
func (r *OAuthProxy) Render(w io.Writer, name string, data interface{}) error {
	return r.templates.ExecuteTemplate(w, name, data)
}
