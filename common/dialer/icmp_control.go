package dialer

// 從 upstream/testing 的 common/dialer 嫁接的兩個方法（本次併 upstream 時，
// auto-merge 把 fork 深度定製的 default*.go 換成上游版、又把上游版整檔還原成
// fork 版，兩邊各丟了一半——這裡按 upstream 原樣補回上游新增的 ICMP 控制，
// 依賴的 selectInterfaces 與欄位 fork 本來就有）：
//   · serialInterfaceControl：按策略選介面並綁定的 control.Func（上游實作）。
//   · ICMPControl：direct 出站的 ICMP echo（ping.NewPort）用的 socket 控制——
//     沒有它 protocol/direct 的 ICMP 支持編不過（fragmentexclave 的同族需求
//     由 fork 自己的 DialerForICMPDestination 滿足，兩者並存）。

import (
	"errors"
	"syscall"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

func (d *DefaultDialer) serialInterfaceControl(strategy constant.NetworkStrategy, interfaceType []constant.InterfaceType, fallbackInterfaceType []constant.InterfaceType) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		primaryInterfaces, fallbackInterfaces := selectInterfaces(d.networkManager, strategy, interfaceType, fallbackInterfaceType)
		if len(primaryInterfaces)+len(fallbackInterfaces) == 0 {
			return E.New("no available network interface")
		}
		defaultInterface := d.networkManager.InterfaceMonitor().DefaultInterface()
		var errors_ []error
		for _, networkInterfaces := range [][]adapter.NetworkInterface{primaryInterfaces, fallbackInterfaces} {
			for _, networkInterface := range networkInterfaces {
				if defaultInterface != nil && networkInterface.Index == defaultInterface.Index {
					return nil
				}
				err := control.BindToInterface0(nil, conn, network, address, networkInterface.Name, networkInterface.Index, false)
				if err == nil {
					return nil
				}
				errors_ = append(errors_, E.Cause(err, "bind ", networkInterface.Name, " (", networkInterface.Index, ")"))
			}
		}
		return E.Errors(errors_...)
	}
}

func (d *DefaultDialer) ICMPControl() control.Func {
	if d.networkStrategy == nil || d.defaultNetworkStrategy && len(d.networkType) == 0 {
		return d.dialer4.Control
	}
	interfaceControl := d.serialInterfaceControl(*d.networkStrategy, d.networkType, d.fallbackNetworkType)
	return control.Append(d.dialer4.Control, func(network, address string, conn syscall.RawConn) error {
		err := interfaceControl(network, address, conn)
		// bind interface failed on legacy xiaomi systems
		if d.defaultNetworkStrategy && errors.Is(err, syscall.EPERM) {
			return nil
		}
		return err
	})
}
