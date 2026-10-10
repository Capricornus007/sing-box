//go:build with_ebpf && (linux || android)

package ebpf

import (
	"slices"
	"strings"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	LC "github.com/sagernet/sing-box/option"

	E "github.com/sagernet/sing/common/exceptions"
	ranges "github.com/sagernet/sing/common/ranges"

	tun "github.com/sagernet/sing-tun"
)

const androidUserRange = 100000

type androidUIDOptions struct {
	includeAndroidUser []int
	includePackage     []string
	excludePackage     []string
}

func newAndroidUIDOptions(options LC.EBPFLocal) *androidUIDOptions {
	if !hasAndroidUIDOptions(options) {
		return nil
	}
	return &androidUIDOptions{
		includeAndroidUser: slices.Clone(options.IncludeAndroidUser),
		includePackage:     slices.Clone(options.IncludePackage),
		excludePackage:     slices.Clone(options.ExcludePackage),
	}
}

func (i *Inbound) resolveAndroidUIDPolicy() error {
	packageManager, err := androidPackageManager()
	if (len(i.androidUIDOptions.includePackage) > 0 || len(i.androidUIDOptions.excludePackage) > 0) && err != nil {
		return E.Cause(err, "Android package manager is unavailable")
	}
	warnSharedUID := make(map[uint32]struct{})
	i.inspectAndroidPackages(packageManager, "include", i.androidUIDOptions.includePackage, warnSharedUID)
	i.inspectAndroidPackages(packageManager, "exclude", i.androidUIDOptions.excludePackage, warnSharedUID)
	includeUID, excludeUID := resolveAndroidUIDRanges(i.cgroupPolicy, i.androidUIDOptions, packageManager)
	i.cgroupPolicy.IncludeUID = includeUID
	i.cgroupPolicy.ExcludeUID = excludeUID
	logInfof("[EBPF] resolved Android UID policy at startup: include_ranges=%d, exclude_ranges=%d",
		len(i.cgroupPolicy.IncludeUID),
		len(i.cgroupPolicy.ExcludeUID),
	)
	return nil
}

// resolveAndroidUIDRanges expands the Android user/package policy into concrete
// UID ranges, preserving any pre-existing include/exclude UID ranges.
func resolveAndroidUIDRanges(
	policy ECommon.CgroupPolicy,
	options *androidUIDOptions,
	packageManager tun.PackageManager,
) ([]ECommon.UIDRange, []ECommon.UIDRange) {
	tunOptions := tun.Options{
		IncludeUID:         toTunUIDRanges(policy.IncludeUID),
		ExcludeUID:         toTunUIDRanges(policy.ExcludeUID),
		IncludeAndroidUser: slices.Clone(options.includeAndroidUser),
		IncludePackage:     slices.Clone(options.includePackage),
		ExcludePackage:     slices.Clone(options.excludePackage),
	}
	tunOptions.BuildAndroidRules(packageManager)
	return fromTunUIDRanges(tunOptions.IncludeUID), fromTunUIDRanges(tunOptions.ExcludeUID)
}

func (i *Inbound) inspectAndroidPackages(packageManager tun.PackageManager, mode string, packageNames []string, warnedSharedUID map[uint32]struct{}) {
	if packageManager == nil {
		return
	}
	for _, packageName := range packageNames {
		packageID, loaded := packageManager.IDBySharedPackage(packageName)
		if !loaded {
			packageID, loaded = packageManager.IDByPackage(packageName)
		}
		if !loaded {
			logWarnf("[EBPF] %s_package not found at startup: %s; 裝好這個應用或它的 UID 變動後重連一次", mode, packageName)
			continue
		}
		if _, warned := warnedSharedUID[packageID]; warned {
			continue
		}
		sharedPackages, loaded := packageManager.PackagesByID(packageID)
		if !loaded || len(sharedPackages) < 2 {
			continue
		}
		warnedSharedUID[packageID] = struct{}{}
		logWarnf("[EBPF] Android packages [%s] share UID %d; eBPF UID policy applies to all of them", strings.Join(sharedPackages, ", "), packageID)
	}
}

func toTunUIDRanges(uidRanges []ECommon.UIDRange) []ranges.Range[uint32] {
	converted := make([]ranges.Range[uint32], 0, len(uidRanges))
	for _, uidRange := range uidRanges {
		converted = append(converted, ranges.New(uidRange.Start, uidRange.End))
	}
	return converted
}

func fromTunUIDRanges(uidRanges []ranges.Range[uint32]) []ECommon.UIDRange {
	converted := make([]ECommon.UIDRange, 0, len(uidRanges))
	for _, uidRange := range uidRanges {
		converted = append(converted, ECommon.UIDRange{Start: uidRange.Start, End: uidRange.End})
	}
	return converted
}
