package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/nekoutils"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// NekoBox names the rule sets it builds from geoip.db and geosite.db geoip:<code> and geosite:<name>.
func TestLocalRuleSetReadsNekoGeoNames(t *testing.T) {
	geosite, geoip := nekoutils.GetGeoSiteHeadlessRules, nekoutils.GetGeoIPHeadlessRules
	t.Cleanup(func() { nekoutils.GetGeoSiteHeadlessRules, nekoutils.GetGeoIPHeadlessRules = geosite, geoip })
	newSet := func(path string) (*LocalRuleSet, error) {
		return NewLocalRuleSet(context.Background(), log.NewNOPFactory().Logger(), path, option.RuleSet{
			Type:         C.RuleSetTypeLocal,
			Format:       C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{Path: path},
		})
	}

	// Without the readers libcore registers, the name is a file path as upstream reads it.
	nekoutils.GetGeoSiteHeadlessRules, nekoutils.GetGeoIPHeadlessRules = nil, nil
	_, err := newSet("geosite:category-ads-all")
	require.Error(t, err)

	var asked []string
	nekoutils.GetGeoSiteHeadlessRules = func(name string) ([]option.HeadlessRule, error) {
		asked = append(asked, "geosite "+name)
		return []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: badoption.Listable[string]{"ads.example"}}}}, nil
	}
	nekoutils.GetGeoIPHeadlessRules = func(name string) ([]option.HeadlessRule, error) {
		asked = append(asked, "geoip "+name)
		return []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{IPCIDR: badoption.Listable[string]{"198.51.100.0/24"}}}}, nil
	}
	site, err := newSet("geosite:category-ads-all")
	require.NoError(t, err)
	ip, err := newSet("geoip:ru")
	require.NoError(t, err)
	require.Equal(t, []string{"geosite category-ads-all", "geoip ru"}, asked)

	domain := &adapter.InboundContext{Domain: "x.ads.example"}
	domain.ResetRuleCache()
	require.True(t, site.Match(domain))
	address := &adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("198.51.100.7", 443)}
	address.ResetRuleCache()
	require.True(t, ip.Match(address))
	require.True(t, ip.Metadata().ContainsIPCIDRRule)

	// Other names stay file paths, and a reader's error stops the rule set.
	_, err = newSet("missing.srs")
	require.Error(t, err)
	nekoutils.GetGeoSiteHeadlessRules = func(string) ([]option.HeadlessRule, error) { return nil, context.Canceled }
	_, err = newSet("geosite:unknown")
	require.ErrorIs(t, err, context.Canceled)
}
