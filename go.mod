module github.com/MicahParks/keyfunc

go 1.16

require github.com/golang-jwt/jwt/v4 v4.4.2

retract v1.3.0 // Contains a bug in ResponseExtractorStatusOK where the *http.Response body is not closed. https://github.com/MicahParks/keyfunc/issues/51
