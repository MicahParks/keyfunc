module github.com/MicahParks/keyfunc

go 1.16

require (
	github.com/golang-jwt/jwt/v5 v5.0.0-20220827114201-5735b9c09c4f
)

retract v1.3.0 // Contains a bug in ResponseExtractorStatusOK where the *http.Response body is not closed. https://github.com/MicahParks/keyfunc/issues/51
