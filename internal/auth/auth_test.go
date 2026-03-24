package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name           string
		testHeaders    http.Header
		expectedError  error
		expectedAPIKey string
	}{
		{
			name:           "no auth header",
			testHeaders:    http.Header{},
			expectedError:  ErrNoAuthHeaderIncluded,
			expectedAPIKey: "",
		},
		{
			name:           "empty auth header",
			testHeaders:    http.Header{"Authorization": []string{""}},
			expectedError:  ErrNoAuthHeaderIncluded,
			expectedAPIKey: "",
		},
		{
			name:           "bad auth header shape",
			testHeaders:    http.Header{"Authorization": []string{"lasdkjf"}},
			expectedError:  errors.New("malformed authorization header"),
			expectedAPIKey: "",
		},
		{
			name:           "bad auth header prefix",
			testHeaders:    http.Header{"Authorization": []string{"foo bar"}},
			expectedError:  errors.New("malformed authorization header"),
			expectedAPIKey: "",
		},
		{
			name:           "happy path",
			testHeaders:    http.Header{"Authorization": []string{"ApiKey bar"}},
			expectedError:  nil,
			expectedAPIKey: "bar",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.testHeaders)
			if tc.expectedError != nil {
				require.EqualError(t, err, tc.expectedError.Error())
			}
			require.Equal(t, tc.expectedAPIKey, key)
		})
	}
}
