package wireproxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sync"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	fmt.Fprintf(&request, "private_key=%s\n", conf.SecretKey)

	if conf.ListenPort != nil {
		fmt.Fprintf(&request, "listen_port=%d\n", *conf.ListenPort)
	}

	for _, peer := range conf.Peers {
		fmt.Fprintf(&request, heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		)
		if peer.Endpoint != nil {
			fmt.Fprintf(&request, "endpoint=%s\n", *peer.Endpoint)
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				fmt.Fprintf(&request, "allowed_ip=%s\n", ip.String())
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}

func newDeviceLogger(level int, w io.Writer) *device.Logger {
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	logf := func(prefix string) func(string, ...any) {
		return log.New(w, prefix+": ", log.Ldate|log.Ltime).Printf
	}
	if level >= device.LogLevelVerbose {
		logger.Verbosef = logf("DEBUG")
	}
	if level >= device.LogLevelError {
		logger.Errorf = logf("ERROR")
	}
	return logger
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *Configuration, logLevel int, logWriter io.Writer) (*VirtualTun, error) {
	deviceConf := conf.Device
	setting, err := CreateIPCRequest(deviceConf)
	if err != nil {
		return nil, err
	}

	log.Printf("Creating WireGuard device: addresses=%v, DNS=%v, MTU=%d", setting.DeviceAddr, setting.DNS, setting.MTU)
	for i, peer := range deviceConf.Peers {
		endpoint := "<none>"
		if peer.Endpoint != nil {
			endpoint = *peer.Endpoint
		}
		log.Printf("  Peer %d: endpoint=%s, keepalive=%ds, allowedIPs=%v", i+1, endpoint, peer.KeepAlive, peer.AllowedIPs)
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), newDeviceLogger(logLevel, logWriter))
	err = dev.IpcSet(setting.IpcRequest)
	if err != nil {
		dev.Close()
		return nil, err
	}
	log.Printf("WireGuard device configured successfully")

	err = dev.Up()
	if err != nil {
		dev.Close()
		return nil, err
	}
	log.Printf("WireGuard device is up")

	hasV4 := false
	hasV6 := false
	for _, addr := range setting.DeviceAddr {
		if addr.Is4() {
			hasV4 = true
		}
		if addr.Is6() {
			hasV6 = true
		}
	}

	if conf.Resolve.ResolveStrategy == "auto" {
		if hasV4 && !hasV6 {
			conf.Resolve.ResolveStrategy = "ipv4"
		} else {
			conf.Resolve.ResolveStrategy = "ipv6"
		}
	}
	log.Printf("Resolve strategy: %s", conf.Resolve.ResolveStrategy)

	return &VirtualTun{
		Tnet:           tnet,
		Dev:            dev,
		Conf:           deviceConf,
		ResolveConfig:  conf.Resolve,
		SystemDNS:      len(setting.DNS) == 0,
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}, nil
}
