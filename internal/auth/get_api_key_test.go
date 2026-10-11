package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - Missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer some-random-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header - Only Prefix No Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid ApiKey Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key-123"},
			},
			expectedKey:   "my-secret-api-key-123",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

		
			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() gotKey = %v, want %v", gotKey, tt.expectedKey)
			}

		
			if tt.expectedError == nil {
				if gotErr != nil {
					t.Errorf("GetAPIKey() unexpected error: %v", gotErr)
				}
			} else {
				if gotErr == nil {
					t.Errorf("GetAPIKey() expected error %v, got nil", tt.expectedError)
				} else if gotErr.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.expectedError)
				}
			}
		})
	}
}
