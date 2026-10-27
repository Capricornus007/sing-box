//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"

	mDNS "github.com/miekg/dns"
)

func TestDNSTransportExchangeMostSpecificRoute(t *testing.T) {
	for _, test := range []struct {
		name           string
		question       string
		routes         map[string][]string
		disableDefault bool
		wantResolvers  []string
		wantRcode      int
		wantError      error
	}{
		{
			name:     "nested suffixes",
			question: "host.dev.example.com.",
			routes: map[string][]string{
				"com.":             {"top"},
				"example.com.":     {"parent"},
				"dev.example.com.": {"child"},
			},
			wantResolvers: []string{"child"},
		},
		{
			name:     "exact child suffix",
			question: "dev.example.com.",
			routes: map[string][]string{
				"example.com.":     {"parent"},
				"dev.example.com.": {"child"},
			},
			wantResolvers: []string{"child"},
		},
		{
			name:     "sibling uses parent",
			question: "host.prod.example.com.",
			routes: map[string][]string{
				"example.com.":     {"parent"},
				"dev.example.com.": {"child"},
			},
			wantResolvers: []string{"parent"},
		},
		{
			name:     "root loses to specific suffix",
			question: "host.example.com.",
			routes: map[string][]string{
				".":            {"root"},
				"example.com.": {"specific"},
			},
			wantResolvers: []string{"specific"},
		},
		{
			name:     "root matches unrelated name",
			question: "host.example.net.",
			routes: map[string][]string{
				".":            {"root"},
				"example.com.": {"specific"},
			},
			disableDefault: true,
			wantResolvers:  []string{"root"},
		},
		{
			name:     "empty parent does not hide child",
			question: "host.dev.example.com.",
			routes: map[string][]string{
				"example.com.":     nil,
				"dev.example.com.": {"child"},
			},
			wantResolvers: []string{"child"},
		},
		{
			name:     "empty child is authoritative",
			question: "host.dev.example.com.",
			routes: map[string][]string{
				".":                {"root"},
				"example.com.":     {"parent"},
				"dev.example.com.": nil,
			},
			wantRcode: mDNS.RcodeNameError,
		},
		{
			name:     "empty parent matches sibling",
			question: "host.prod.example.com.",
			routes: map[string][]string{
				"example.com.":     nil,
				"dev.example.com.": {"child"},
			},
			wantRcode: mDNS.RcodeNameError,
		},
		{
			name:     "empty root is authoritative",
			question: "host.example.net.",
			routes: map[string][]string{
				".":            nil,
				"example.com.": {"specific"},
			},
			wantRcode: mDNS.RcodeNameError,
		},
		{
			name:     "child label boundary",
			question: "host.notdev.example.com.",
			routes: map[string][]string{
				"example.com.":     {"parent"},
				"dev.example.com.": {"child"},
			},
			wantResolvers: []string{"parent"},
		},
		{
			name:     "unmatched label boundary uses default",
			question: "host.notexample.com.",
			routes: map[string][]string{
				"example.com.": {"parent"},
			},
			wantResolvers: []string{"default"},
		},
		{
			name:     "canonical case with trailing dot",
			question: "HOST.DeV.ExAmPlE.CoM.",
			routes: map[string][]string{
				"example.com.":     {"parent"},
				"dev.example.com.": {"child"},
			},
			wantResolvers: []string{"child"},
		},
		{
			name:     "canonical case without trailing dot",
			question: "HOST.DeV.ExAmPlE.CoM",
			routes: map[string][]string{
				"example.com.":     {"parent"},
				"dev.example.com.": {"child"},
			},
			wantResolvers: []string{"child"},
		},
		{
			name:     "unmatched name uses default",
			question: "host.example.net.",
			routes: map[string][]string{
				"example.com.": {"parent"},
			},
			wantResolvers: []string{"default"},
		},
		{
			name:     "unmatched name with default disabled",
			question: "host.example.net.",
			routes: map[string][]string{
				"example.com.": {"parent"},
			},
			disableDefault: true,
			wantError:      dns.RcodeNameError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var queried []string
			newResolver := func(tag string) adapter.DNSTransport {
				return &routeTestDNSTransport{
					TransportAdapter: dns.NewTransportAdapter("test", tag, nil),
					queried:          &queried,
				}
			}
			transport := &DNSTransport{
				routes:                 make(map[string][]adapter.DNSTransport),
				acceptDefaultResolvers: !test.disableDefault,
				defaultResolvers:       []adapter.DNSTransport{newResolver("default")},
			}
			for suffix, tags := range test.routes {
				transport.routes[suffix] = nil
				for _, tag := range tags {
					transport.routes[suffix] = append(transport.routes[suffix], newResolver(tag))
				}
			}
			message := &mDNS.Msg{
				MsgHdr: mDNS.MsgHdr{Id: 1234},
				Question: []mDNS.Question{{
					Name:   test.question,
					Qtype:  mDNS.TypeA,
					Qclass: mDNS.ClassINET,
				}},
			}
			response, err := transport.Exchange(context.Background(), message)
			if !slices.Equal(queried, test.wantResolvers) {
				t.Fatalf("queried resolvers = %v, want %v", queried, test.wantResolvers)
			}
			if !errors.Is(err, test.wantError) {
				t.Fatalf("exchange error = %v, want %v", err, test.wantError)
			}
			if test.wantError != nil {
				if response != nil {
					t.Fatalf("unexpected response on error: %v", response)
				}
				return
			}
			if response == nil {
				t.Fatal("missing response")
			}
			if response.Rcode != test.wantRcode {
				t.Fatalf("response rcode = %v, want %v", response.Rcode, test.wantRcode)
			}
			if !response.Response || response.Id != message.Id || !slices.Equal(response.Question, message.Question) {
				t.Fatalf("response does not match request: %v", response)
			}
		})
	}
}

type routeTestDNSTransport struct {
	dns.TransportAdapter
	queried *[]string
}

func (*routeTestDNSTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*routeTestDNSTransport) Close() error                                   { return nil }
func (*routeTestDNSTransport) Reset()                                         {}

func (t *routeTestDNSTransport) Exchange(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	*t.queried = append(*t.queried, t.Tag())
	return new(mDNS.Msg).SetReply(message), nil
}

func (t *routeTestDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	response, err := t.Exchange(ctx, message)
	callback(response, err)
}
