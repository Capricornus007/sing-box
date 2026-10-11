# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder
LABEL maintainer="nekohasekai <contact-git@sekai.icu>"

# ── builder 吃尖端（golang/go master），不吃發布版 ───────────────────────────
# 用戶 2026-10-11 原話：「docker 的隨便，但我必須看到結果運行的包含最尖端」。
# 官方沒有未發佈版本的二進位（go.dev/dl 只列發布版、go.dev/dl/devel/release.json
# 回 404），所以用本階段那顆發布版 Go 當 GOROOT_BOOTSTRAP、從源碼把尖端編出來。
# 省時：編好的 GOROOT 以 commit 為鍵存進 BuildKit cache mount，同一個尖端只編一次
# （省掉那 15-25 分鐘），之後每次 build 只花幾秒把快取裡那顆 cp 進鏡像。
# GO_TIP_SHA 一定要傳、沒傳就紅：留空靠 layer 快取的話，快取命中時會拿到「上一次的
# 尖端」卻聲稱是尖端——那是騙人。取法：
#   git ls-remote https://github.com/golang/go master | cut -f1
# 兩道 `go version | grep -- -devel` 是硬驗：裝到的不是尖端就讓 build 失敗，不准退回
# 發布版、不准靜默放過（判準同 feed 倉 .github/actions/setup-feed-go 結尾那道）。
ARG GO_TIP_SHA
RUN --mount=type=cache,target=/opt/gotip-cache set -eux; \
    test -n "${GO_TIP_SHA}" || { echo "ERROR: 沒傳 --build-arg GO_TIP_SHA=<golang/go master 的 commit sha>"; exit 1; }; \
    apk add --no-cache git build-base musl-dev; \
    tip="/opt/gotip-cache/${GO_TIP_SHA}/go"; \
    if [ ! -x "$tip/bin/go" ]; then \
        git init -q /tmp/gosrc; \
        git -C /tmp/gosrc remote add origin https://github.com/golang/go; \
        git -C /tmp/gosrc fetch -q --depth 1 origin "${GO_TIP_SHA}"; \
        git -C /tmp/gosrc checkout -q --detach FETCH_HEAD; \
        ( cd /tmp/gosrc/src && GOTOOLCHAIN=local GOROOT_BOOTSTRAP=/usr/local/go ./make.bash ) || { echo "ERROR: 尖端的 make.bash 失敗"; exit 1; }; \
        mkdir -p "$(dirname "$tip")"; \
        mv /tmp/gosrc "$tip"; \
    fi; \
    rm -rf /opt/go-tip; \
    cp -a "$tip" /opt/go-tip; \
    /opt/go-tip/bin/go version; \
    /opt/go-tip/bin/go version | grep -q -- '-devel' || { echo "ERROR: 編出來的不是尖端（go version 沒帶 -devel）"; exit 1; }
ENV GOROOT=/opt/go-tip
ENV PATH=/opt/go-tip/bin:${PATH}
# 不許 go 去下載發布版頂替尖端（setup-feed-go 也是釘 local 的）。
ENV GOTOOLCHAIN=local
# 再驗一次：這一階段之後所有 go 呼叫實際命中的那顆，必須是尖端而不是 base _image 裡
# 的發布版（PATH 順序被人改過、或 /opt/go-tip 不見了，都在這裡紅）。
RUN go version | grep -q -- '-devel' || { echo "ERROR: builder 階段的 go 不是尖端：$(go version)"; exit 1; }

COPY . /go/src/github.com/sagernet/sing-box
WORKDIR /go/src/github.com/sagernet/sing-box
ARG TARGETOS TARGETARCH
ARG GOPROXY=""
ENV GOPROXY ${GOPROXY}
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN set -ex \
    && apk add git build-base \
    && export COMMIT=$(git rev-parse --short HEAD) \
    && export VERSION=$(go run ./cmd/internal/read_tag) \
    && export TAGS=$(cat release/DEFAULT_BUILD_TAGS_OTHERS) \
    && export LDFLAGS_SHARED=$(cat release/LDFLAGS) \
    && go build -v -trimpath -tags "$TAGS" \
        -o /go/bin/sing-box \
        -ldflags "-X \"github.com/sagernet/sing-box/constant.Version=$VERSION\" $LDFLAGS_SHARED -s -w -buildid=" \
        ./cmd/sing-box
# 產物層級的硬驗：`go version <binary>` 讀的是二進位裡埋的 build info，印出來的就是
# 「這顆 sing-box 是哪個 toolchain 編的」。用戶要看到的是這裡，不是配置裡寫了什麼。
RUN go version /go/bin/sing-box
RUN go version /go/bin/sing-box | grep -q -- '-devel' \
    || { echo "ERROR: 產物 sing-box 不是尖端編出來的"; exit 1; }
FROM --platform=$TARGETPLATFORM alpine AS dist
LABEL maintainer="nekohasekai <contact-git@sekai.icu>"
RUN set -ex \
    && apk add --no-cache --upgrade bash tzdata ca-certificates nftables
COPY --from=builder /go/bin/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
