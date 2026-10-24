module github.com/sagernet/sing-box

go 1.28

require (
	filippo.io/age v1.3.2
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828
	github.com/andybalholm/brotli v1.2.6
	github.com/andybalholm/cascadia v1.3.5
	github.com/antchfx/htmlquery v1.3.7
	github.com/antchfx/xpath v1.3.9
	github.com/anthropics/anthropic-sdk-go v1.84.0
	github.com/caddyserver/certmagic v0.25.6
	github.com/caddyserver/zerossl v0.1.6
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/cilium/ebpf v0.22.0
	github.com/coder/websocket v1.8.15
	github.com/creack/pty v1.1.24
	github.com/cretz/bine v0.2.0
	github.com/database64128/tfo-go/v2 v2.4.2
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca
	github.com/enfein/mieru/v3 v3.38.2
	github.com/go-chi/chi/v5 v5.5.0
	github.com/go-chi/render v1.0.3
	github.com/goccy/go-json v0.11.2
	github.com/godbus/dbus/v5 v5.2.4
	github.com/gofrs/uuid/v5 v5.5.1
	github.com/insomniacslk/dhcp v0.0.0-20261014062924-c6bb46ad3f3a
	github.com/jsimonetti/rtnetlink v1.4.2
	github.com/keybase/go-keychain v0.0.1
	github.com/klauspost/compress v1.20.3
	github.com/klauspost/cpuid/v2 v2.4.1
	github.com/libdns/acmedns v0.5.0
	github.com/libdns/alidns v1.0.7
	github.com/libdns/cloudflare v0.2.2
	github.com/libdns/libdns v1.1.1
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mattn/go-runewidth v0.0.31
	github.com/mdlayher/netlink v1.11.2
	github.com/metacubex/mihomo v1.19.33
	github.com/metacubex/utls v1.8.8
	github.com/mholt/acmez/v3 v3.1.7
	github.com/miekg/dns v1.1.73
	github.com/openai/openai-go/v3 v3.85.1
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/pkg/sftp v1.13.11
	github.com/sagernet/asc-go v0.0.0-20260914163356-9e3d45a797c1
	github.com/sagernet/bbolt v0.0.0-20260915102804-500ee1e84832
	github.com/sagernet/cors v1.2.1
	github.com/sagernet/cronet-go v0.0.0-20260929213745-4d18a60dc3a8
	github.com/sagernet/cronet-go/all v0.0.0-20260929213745-4d18a60dc3a8
	github.com/sagernet/fswatch v0.1.2
	github.com/sagernet/gliderssh v0.3.4-0.20260531100337-2194faca5648
	github.com/sagernet/gomobile v0.1.13
	github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1
	github.com/sagernet/netlink v0.0.0-20260919000536-5d76abd97cf7
	github.com/sagernet/nftables v0.3.0-mod.4
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.12
	github.com/sagernet/sing v0.9.7-0.20261022215834-56e8e9fb54a4
	github.com/sagernet/sing-anytls v0.0.0-20260928104022-580984e4d8cb
	github.com/sagernet/sing-cloudflared v0.1.4-0.20261002084126-c1255ae368f2
	github.com/sagernet/sing-mux v0.3.10-0.20260929204512-caf09fe32475
	github.com/sagernet/sing-openconnect v0.1.1-0.20260929151226-29757281a247
	github.com/sagernet/sing-openvpn v0.1.1-0.20260929151220-f330676d6d4a
	github.com/sagernet/sing-quic v0.7.2-0.20261002084117-75c3ac4fa12b
	github.com/sagernet/sing-shadowsocks v0.2.9-0.20260929204512-65740e0f0e3e
	github.com/sagernet/sing-shadowsocks2 v0.2.2-0.20260929152114-a69d1086332b
	github.com/sagernet/sing-shadowtls v0.2.2-0.20260928201441-a9c0127d5c99
	github.com/sagernet/sing-snell v0.0.0-20260904135315-bc5a12ac736f
	github.com/sagernet/sing-tun v0.9.7-0.20261022224154-1af57d7f3a23
	github.com/sagernet/sing-usbip v0.0.0-20260817040617-28bd42667eca
	github.com/sagernet/sing-vmess v0.2.9-0.20260929152519-9b95ab8c9478
	github.com/sagernet/smux v1.5.50-sing-box-mod.1
	github.com/sagernet/tailscale v1.102.1-sing-box-1.14-mod.5.0.20260925112514-35e61219dedd
	github.com/sagernet/wireguard-go v0.0.8-0.20261022215849-fdf0ad046586
	github.com/sagernet/ws v0.0.0-20231204124109-acfe8907c854
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.12.1
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55
	github.com/vishvananda/netns v0.0.5
	github.com/wasilibs/go-re2 v1.13.0
	go.uber.org/zap v1.28.0
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb
	golang.org/x/crypto v0.58.0
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e
	golang.org/x/mod v0.42.0
	golang.org/x/net v0.61.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	golang.org/x/term v0.47.0
	golang.org/x/text v0.43.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
	howett.net/plist v1.0.1
	lukechampine.com/blake3 v1.4.1
)

require (
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/ajg/form v1.9.0 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/anchore/go-lzo v0.1.1 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/axiomhq/hyperloglog v0.3.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.6.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/coreos/go-oidc/v3 v3.21.0 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/dgryski/go-metro v0.0.0-20261008173524-5059e0b1da03 // indirect
	github.com/ebitengine/purego v0.11.2 // indirect
	github.com/florianl/go-nfqueue/v2 v2.1.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.6 // indirect
	github.com/gaissmai/bart v0.30.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go4org/hashtriemap v0.0.0-20260925222741-44e5305f85d9 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/certificate-transparency-go v1.4.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/nftables v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/invopop/jsonschema v0.14.0 // indirect
	github.com/jackpal/go-nat-pmp v1.1.0 // indirect
	github.com/kamstrup/intmap v0.5.2 // indirect
	github.com/koron/go-ssdp v0.9.1 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138 // indirect
	github.com/libp2p/go-netroute v0.4.0 // indirect
	github.com/mdlayher/socket v0.8.0 // indirect
	github.com/metacubex/chacha v0.1.5 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	github.com/metacubex/sing v0.5.8 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/pb33f/go-yaml v0.1.1 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.2 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.33 // indirect
	github.com/pion/dtls/v3 v3.1.15 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v5 v5.1.1 // indirect
	github.com/pires/go-proxyproto v0.16.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/sagernet/cronet-go/lib/android_386 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/android_amd64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/android_arm v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/android_arm64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/darwin_amd64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/darwin_arm64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/ios_amd64_simulator v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64_simulator v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_386 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_386_musl v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64_musl v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_arm v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64_musl v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_arm_musl v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64_musl v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_mips64le v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle_musl v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64_musl v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/tvos_amd64_simulator v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64_simulator v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/windows_amd64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sagernet/cronet-go/lib/windows_arm64 v0.0.0-20260929213014-a1cafd93eb1f // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/smallstep/pkcs7 v0.2.3 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/standard-webhooks/standard-webhooks/libraries v0.0.1 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tailscale/netlink v1.1.1-0.20240822203006-4d49adab4de7 // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20260917222731-e0ed2d0d0fea // indirect
	github.com/tidwall/gjson v1.20.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.2 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v1.1.1 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261019180522-ce908d29299b // indirect
	gvisor.dev/gvisor v0.0.0-20261023011047-40e83675f642 // indirect
	zombiezen.com/go/capnproto2 v2.18.2+incompatible // indirect
)

replace github.com/amnezia-vpn/amneziawg-go/v3 => github.com/Capricornus007/amneziawg-go/v3 v3.1.20261008-mod.5

replace github.com/sagernet/sing => github.com/Capricornus007/sing v0.9.5-0.20261023032553-61708a50b695

replace github.com/sagernet/sing-snell => github.com/Capricornus007/sing-snell v0.0.0-20261023034450-2a45f12a2599

replace github.com/sagernet/sing-tun => github.com/Capricornus007/sing-tun v0.9.6-sing-box-fork.0.20261024002847

replace github.com/sagernet/quic-go => github.com/Capricornus007/quic-go v0.61.0-sing-box-mod.9.0.20261023034407-c7b0124a13f8

replace github.com/sagernet/sing-quic => github.com/Capricornus007/sing-quic v0.7.0-beta.2.0.20261023034421-e8d980d7061e

replace github.com/sagernet/sing-mux => github.com/Capricornus007/sing-mux v0.3.7-0.20261023034436-b5ac5e2ea4b4

replace github.com/sagernet/tailscale => github.com/Capricornus007/tailscale v1.102.1-sing-box-1.14-mod.5.0.20261023034533-b3c1784682e2

replace github.com/sagernet/sing-vmess => github.com/Capricornus007/sing-vmess v0.2.8-mod.1-nb4a.0.20261023034519-134c8fa39a32

replace github.com/sagernet/wireguard-go => github.com/Capricornus007/wireguard-go v0.0.6-mod.1.0.20261023032835-5bd3301fdba3

replace github.com/metacubex/utls => github.com/Capricornus007/utls v1.8.8-0.20261023032810-2c28a526ca61

replace gvisor.dev/gvisor => github.com/Capricornus007/gvisor-awg v0.0.0-20261023032907-eaadebffb9ac

replace github.com/refraction-networking/utls => github.com/Capricornus007/utls v1.8.8-0.20261023032810-2c28a526ca61
