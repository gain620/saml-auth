package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/crewjam/saml/samlsp"
	"net/http"
	"net/url"
)

// Print SAML request
func samlRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//fmt.Printf("%+v\n", r)
		next.ServeHTTP(w, r)
	})
}

// Echo session info
func echoSession(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%v\n", samlsp.SessionFromContext(r.Context()))
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cer", "myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("http://localhost:8080/realms/gain/protocol/saml/descriptor")
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})

	app := http.HandlerFunc(echoSession)
	http.Handle("/hello", samlSP.RequireAccount(app))

	http.Handle("/saml/", samlRequestMiddleware(samlSP))
	http.ListenAndServe(":8000", nil)
}
