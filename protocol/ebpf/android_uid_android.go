//go:build with_ebpf && android

package ebpf

import (
	"os/exec"
	"strconv"
	"strings"
	"sync"

	tun "github.com/sagernet/sing-tun"
)

// suPackageManager 用 root shell 問 pm 來解析 package→UID。
//
// libbox 下 sing-box 是把 package 名單原封不動交給 Kotlin 決定路由，
// 但 eBPF 的 UID 策略必須在 Go 側寫進 map，那條路在這裡用不了；
// 而 eBPF 模式本來就以 root 為前提，所以直接問 pm 不必新增 Kotlin 橋。
type suPackageManager struct {
	access    sync.RWMutex
	idByName  map[string]uint32
	namesByID map[uint32][]string
}

func androidPackageManager() (tun.PackageManager, error) {
	manager := &suPackageManager{
		idByName:  make(map[string]uint32),
		namesByID: make(map[uint32][]string),
	}
	if err := manager.Start(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *suPackageManager) Start() error {
	output, err := exec.Command("su", "-c", "pm list packages -U").CombinedOutput()
	if err != nil {
		return err
	}
	idByName := make(map[string]uint32)
	namesByID := make(map[uint32][]string)
	for _, line := range strings.Split(string(output), "\n") {
		name, uid, loaded := parsePackageUIDLine(line)
		if !loaded {
			continue
		}
		if _, duplicate := idByName[name]; !duplicate {
			idByName[name] = uid
		}
		namesByID[uid] = append(namesByID[uid], name)
	}
	m.access.Lock()
	m.idByName = idByName
	m.namesByID = namesByID
	m.access.Unlock()
	return nil
}

// parsePackageUIDLine 解析 `package:<name> uid:<n>`，缺 uid 的行動模擬器會只回包名，此時丟棄。
func parsePackageUIDLine(line string) (string, uint32, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "package:") {
		return "", 0, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[1], "uid:") {
		return "", 0, false
	}
	uid, err := strconv.ParseUint(strings.TrimPrefix(fields[1], "uid:"), 10, 32)
	if err != nil {
		return "", 0, false
	}
	return strings.TrimPrefix(fields[0], "package:"), uint32(uid), true
}

func (m *suPackageManager) Close() error {
	return nil
}

func (m *suPackageManager) IDByPackage(packageName string) (uint32, bool) {
	m.access.RLock()
	defer m.access.RUnlock()
	uid, loaded := m.idByName[packageName]
	return uid, loaded
}

// IDBySharedPackage 一律回 false：呼叫端（BuildAndroidRules、inspectAndroidPackages）
// 都是「先試 shared 再試 package」的順序，所以退回 IDByPackage 是安全的。
// sharedUserId 的查詢需要 Android framework 層，pm 沒有對應輸出，這裡不假裝支援。
func (m *suPackageManager) IDBySharedPackage(sharedPackage string) (uint32, bool) {
	return 0, false
}

func (m *suPackageManager) PackageByID(id uint32) (string, bool) {
	m.access.RLock()
	defer m.access.RUnlock()
	names, loaded := m.namesByID[id]
	if !loaded || len(names) == 0 {
		return "", false
	}
	return names[0], true
}

func (m *suPackageManager) PackagesByID(id uint32) ([]string, bool) {
	m.access.RLock()
	defer m.access.RUnlock()
	names, loaded := m.namesByID[id]
	return names, loaded
}

func (m *suPackageManager) SharedPackageByID(id uint32) (string, bool) {
	return "", false
}
