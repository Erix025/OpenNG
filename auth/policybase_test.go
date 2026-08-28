package auth

import "testing"

func TestWebsocketAuthBypassed(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "orca", host: "orca.erix025.me", want: true},
		{name: "orca with port", host: "orca.erix025.me:443", want: true},
		{name: "case insensitive", host: "ORCA.ERIX025.ME", want: true},
		{name: "browser", host: "web.erix025.me", want: false},
		{name: "unknown", host: "example.com", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := websocketAuthBypassed(test.host); got != test.want {
				t.Fatalf("websocketAuthBypassed(%q) = %v, want %v", test.host, got, test.want)
			}
		})
	}
}
