package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/code-ready/gvisor-tap-vsock/pkg/transport"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/code-ready/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	debug        bool
	mtu          int
	endpoints    arrayFlags
	vpnkitSocket string
	qemuSocket   string
	sshPort      int
	pidFile      string
)

func main() {
	flag.Var(&endpoints, "listen", fmt.Sprintf("Url where the tap send packets (default %s)", transport.DefaultURL))
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 1500, "mtu")
	flag.IntVar(&sshPort, "ssh-port", 2222, "Port to access the guest virtual machine. Must be between 1024 and 65535")
	flag.StringVar(&vpnkitSocket, "listen-vpnkit", "", "VPNKit socket to be used by Hyperkit")
	flag.StringVar(&qemuSocket, "listen-qemu", "", "Socket to be used by Qemu")
	flag.StringVar(&pidFile, "pid-file", "", "Generate a file with the PID in it")
	flag.Parse()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	if len(endpoints) == 0 {
		endpoints = append(endpoints, transport.DefaultURL)
	}

	if _, err := url.Parse(qemuSocket); err != nil {
		exitWithError(errors.New("invalid value for listen-qemu"))
	}

	if vpnkitSocket != "" && qemuSocket != "" {
		exitWithError(errors.New("cannot use qemu and vpnkit protocol at the same time"))
	}
	// If the given port is not between the privileged ports
	// and the oft considered maximum port, return an error.
	if sshPort < 1024 || sshPort > 65535 {
		exitWithError(errors.New("ssh-port value must be between 1024 and 65535"))
	}
	protocol := types.HyperKitProtocol
	if qemuSocket != "" {
		protocol = types.QemuProtocol
	}

	// Create a PID file if requested
	if len(pidFile) > 0 {
		f, err := os.Create(pidFile)
		if err != nil {
			exitWithError(err)
		}
		defer func() {
			fmt.Println("11111111111111111111111111111111111111")
			if err := os.Remove(pidFile); err != nil {
				log.Error(err)
			}
		}()
		pid := os.Getppid()
		if _, err := f.WriteString(strconv.Itoa(pid)); err != nil {
			exitWithError(err)
		}
	}

	// Catch signals so exits are graceful and defers can run
	closeHandler(ctx, cancel)
	fmt.Println("22222222222222")
	if err := run(ctx, cancel, &types.Configuration{
		Debug:             debug,
		CaptureFile:       captureFile(),
		MTU:               mtu,
		Subnet:            "192.168.127.0/24",
		GatewayIP:         "192.168.127.1",
		GatewayMacAddress: "5a:94:ef:e4:0c:dd",
		DHCPStaticLeases: map[string]string{
			"192.168.127.2": "5a:94:ef:e4:0c:ee",
		},
		DNS: []types.Zone{
			{
				Name:      "apps-crc.testing.",
				DefaultIP: net.ParseIP("192.168.127.2"),
			},
			{
				Name: "crc.testing.",
				Records: []types.Record{
					{
						Name: "gateway",
						IP:   net.ParseIP("192.168.127.1"),
					},
					{
						Name: "host",
						IP:   net.ParseIP("192.168.127.254"),
					},
					{
						Name: "api",
						IP:   net.ParseIP("192.168.127.2"),
					},
					{
						Name: "api-int",
						IP:   net.ParseIP("192.168.127.2"),
					},
					{
						Regexp: regexp.MustCompile("crc-(.*?)-master-0"),
						IP:     net.ParseIP("192.168.126.11"),
					},
				},
			},
		},
		Forwards: map[string]string{
			fmt.Sprintf(":%s", strconv.Itoa(sshPort)): "192.168.127.2:22",
		},
		NAT: map[string]string{
			"192.168.127.254": "127.0.0.1",
		},
		VpnKitUUIDMacAddresses: map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
		},
		Protocol: protocol,
	}, endpoints); err != nil {
		exitWithError(err)
	}
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func captureFile() string {
	if !debug {
		return ""
	}
	return "capture.pcap"
}

func run(ctx context.Context, cancel context.CancelFunc, configuration *types.Configuration, endpoints []string) error {
	vn, err := virtualnetwork.New(configuration)
	if err != nil {
		return err
	}
	log.Info("waiting for clients...")
	errCh := make(chan error)

	for _, endpoint := range endpoints {
		log.Infof("listening %s", endpoint)
		ln, err := transport.Listen(endpoint)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}

		go func() {
			if err := http.Serve(ln, withProfiler(vn)); err != nil && err != http.ErrServerClosed {
				errCh <- err
				fmt.Println("8")
				return
			}
		}()
	}
	// TODO: only run when debug?
	go func() {
		for {
			select {
			case <-time.After(5 * time.Second):
				fmt.Printf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
			case <-ctx.Done():
				fmt.Println("7")
				return
			}
		}
	}()

	if vpnkitSocket != "" {
		vpnkitListener, err := transport.Listen(vpnkitSocket)
		if err != nil {
			return err
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					fmt.Println("6")
					return
				default:
				}
				conn, err := vpnkitListener.Accept()
				if err != nil {
					log.Errorf("vpnkit accept error: %s", err)
					continue
				}
				go func() {
					if err := vn.AcceptVpnKit(conn); err != nil {
						log.Errorf("vpnkit error: %s", err)
					}
				}()
			}
		}()
	}

	if qemuSocket != "" {
		qemuListener, err := transport.Listen(qemuSocket)
		if err != nil {
			return err
		}
		defer func() {
			if err := qemuListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", qemuSocket, err)
			}
		}()
		go func() {
			for {
				select {
				case <-ctx.Done():
					fmt.Println("5")
					return
				default:
				}
				conn, err := qemuListener.Accept()
				if err != nil {
					log.Errorf("qemu accept error: %s", err)
					cancel()
				}
				go func() {
					if err := vn.AcceptQemu(conn); err != nil {
						log.Errorf("qemu error: %s", err)
					}
				}()
			}
		}()
	}

	ln, err := vn.Listen("tcp", fmt.Sprintf("%s:8080", configuration.GatewayIP))
	if err != nil {
		return err
	}
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte(`Hello world!\n`))
		})
		if err := http.Serve(ln, mux); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
	}()
	return <-errCh
}

func withProfiler(vn *virtualnetwork.VirtualNetwork) http.Handler {
	mux := vn.Mux()
	if debug {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	}
	return mux
}

func exitWithError(err error) {
	log.Error(err)
	os.Exit(1)
}

func closeHandler(ctx context.Context, cancelFunc context.CancelFunc) {
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("3")
		cancelFunc()
		fmt.Println("4")
	}()
}
