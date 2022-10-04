package client

type authorizationStatus string
type challengeStatus string

const (
	AUTHORIZATION_PENDING     authorizationStatus = "pending"
	AUTHORIZATION_VALID       authorizationStatus = "valid"
	AUTHORIZATION_INVALID     authorizationStatus = "invalid"
	AUTHORIZATION_DEACTIVATED authorizationStatus = "deactivated"
	AUTHORIZATION_EXPIRED     authorizationStatus = "expired"
	AUTHORIZATION_REVOKED     authorizationStatus = "revoked"
)

const (
	CHALLENGE_PENDING    challengeStatus = "pending"
	CHALLENGE_PROCESSING challengeStatus = "processing"
	CHALLENGE_VALID      challengeStatus = "valid"
	CHALLENGE_INVALID    challengeStatus = "invalid"
)

// An ACME authorization object represents a server's authorization for
// an account to represent an identifier.
type authorization struct {
	Identifier identifier          `json:"identifier,omitempty"`
	Status     authorizationStatus `json:"status,omitempty"`
	Challenges []challenge         `json:"challenges,omitempty"`
	Wildcard   bool                `json:"wildcard,omitempty"`
	// expires
}

// An ACME challenge object represents a server's offer to validate a
// client's possession of an identifier in a specific way.
type challenge struct {
	// content depends on challenge TODO -> RFC Section 8
}

func (c *client) fetchChallenges() error {
	return nil
}

func (c *client) repondToChallenges() error {
	return nil
}

func (c *client) pollForStatus() error {
	return nil
}
