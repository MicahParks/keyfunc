package jwks

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// Get loads the JWKS at the given URL.
func Get(client *http.Client, u string) (keystore Keystore, err error) {

	// Use the default HTTP client if none was given.
	if client == nil {
		client = http.DefaultClient
	}

	// Get the JWKS as JSON from the given URL.
	var resp *http.Response
	if resp, err = client.Get(u); err != nil {
		return nil, err
	}
	defer resp.Body.Close() // Ignore any error.

	// Read the raw JWKS from the body of the response.
	var keystoreBytes []byte
	if keystoreBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	}

	// Turn the raw JWKS into the correct Go type.
	var rawKS rawKeystore
	if err = json.Unmarshal(keystoreBytes, &rawKS); err != nil {
		return nil, err
	}

	// Iterate through the keys in the raw keystore. Add them to the JWKS.
	keystore = make(map[string]JSONKey, len(rawKS.Keys))
	for _, key := range keystore {
		keystore[key.KeyID] = key
	}

	return keystore, nil
}
