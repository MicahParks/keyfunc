package method

// CustomAlgHeader is the `alg` JSON attribute's value for the example custom jwt.SigningMethod.
const CustomAlgHeader = "customalg"

// EmptyCustom implements the jwt.SigningMethod interface. It will not sign or verify anything.
type EmptyCustom struct{}

// Verify helps implement the jwt.SigningMethod interface. It does not verify.
func (e EmptyCustom) Verify(_ string, _ []byte, _ interface{}) error {
	return nil
}

// Sign helps implement the jwt.SigningMethod interface. It does not sign anything.
func (e EmptyCustom) Sign(_ string, _ interface{}) ([]byte, error) {
	return []byte{}, nil
}

// Alg helps implement the jwt.SigningMethod. It returns the `alg` JSON attribute for JWTs signed with this method.
func (e EmptyCustom) Alg() string {
	return CustomAlgHeader
}
