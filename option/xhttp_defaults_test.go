package option

import (
	"encoding/json"
	"testing"
)

func TestXHTTPPartialXmuxDefaultsPreserveExplicitZero(t *testing.T) {
	for _, input := range []string{`{"h_keep_alive_period":10}`, `{"max_connections":4}`} {
		var options V2RayXHTTPXmuxOptions
		if err := json.Unmarshal([]byte(input), &options); err != nil {
			t.Fatal(err)
		}
		if options.GetNormalizedHMaxRequestTimes().From != 600 || options.GetNormalizedHMaxReusableSecs().From != 1800 {
			t.Fatal("omitted limits lost their defaults")
		}
		if options.MaxConnections.To > 0 && options.GetNormalizedMaxConcurrency().To != 0 {
			t.Fatal("conflicting concurrency default")
		}
	}
	var unlimited V2RayXHTTPXmuxOptions
	if err := json.Unmarshal([]byte(`{"max_concurrency":0,"h_max_request_times":0,"h_max_reusable_secs":0}`), &unlimited); err != nil {
		t.Fatal(err)
	}
	if unlimited.GetNormalizedMaxConcurrency().To != 0 || unlimited.GetNormalizedHMaxRequestTimes().To != 0 || unlimited.GetNormalizedHMaxReusableSecs().To != 0 {
		t.Fatal("explicit unlimited values changed")
	}
	if (&V2RayXHTTPBaseOptions{}).GetNormalizedUplinkDataPlacement() != PlacementAuto {
		t.Fatal("default placement differs from JSON decoding")
	}
}
