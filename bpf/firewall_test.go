package bpf

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/tukejonny/tsundere/bpf/blacklist"
	"github.com/tukejonny/tsundere/bpf/internal/testutil"
)

func TestBan(t *testing.T) {
	var (
		srcMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
		dstMAC, _ = net.ParseMAC("ff:ee:dd:cc:bb:aa")
	)
	tests := []struct {
		name        string
		ether       *layers.Ethernet
		ip          *layers.IPv4
		tcp         *layers.TCP
		pktBytes    []byte
		bannedAddrs []net.IP
		wantAct     testutil.XdpAction
	}{
		{
			name: "pass a packet",
			ether: &layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			ip: &layers.IPv4{
				Version:  4,
				Protocol: layers.IPProtocolTCP,
				Flags:    layers.IPv4DontFragment,
				SrcIP:    net.IP{192, 168, 0, 10},
				DstIP:    net.IP{192, 168, 0, 20},
				TTL:      64,
				IHL:      5,
				Id:       1111,
			},
			tcp: &layers.TCP{
				SrcPort: 12345,
				DstPort: 80,
				Seq:     111,
			},
			bannedAddrs: []net.IP{
				net.IP{192, 168, 0, 100},
			},
			wantAct: testutil.XDP_PASS,
		},
		{
			name: "drop a packet",
			ether: &layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			ip: &layers.IPv4{
				Version:  4,
				Protocol: layers.IPProtocolTCP,
				Flags:    layers.IPv4DontFragment,
				SrcIP:    net.IP{192, 168, 0, 10},
				DstIP:    net.IP{192, 168, 0, 20},
				TTL:      64,
				IHL:      5,
				Id:       1111,
			},
			tcp: &layers.TCP{
				SrcPort: 12345,
				DstPort: 80,
				Seq:     111,
			},
			bannedAddrs: []net.IP{
				net.IP{192, 168, 0, 10},
			},
			wantAct: testutil.XDP_DROP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blMap, err := blacklist.NewBlacklist()
			assert.NoError(t, err)

			bpfProg := blMap.BPFProgram("xdp_prog_firewall")

			for _, bannedAddr := range tt.bannedAddrs {
				err := blMap.Set(bannedAddr)
				assert.NoError(t, err)
			}

			assert.NoError(t, blMap.Pin())
			defer assert.NoError(t, blMap.Unpin())

			tt.tcp.SetNetworkLayerForChecksum(tt.ip)
			pktBytes := testutil.SerializePacket(t,
				tt.ether,
				tt.ip,
				tt.tcp,
			)

			ret, _, err := bpfProg.Test(pktBytes)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAct.String(), testutil.XdpAction(ret).String())

			blMap.Close()
		})
	}
}

func TestDropCounter(t *testing.T) {
	var (
		srcMAC, _  = net.ParseMAC("aa:bb:cc:dd:ee:ff")
		dstMAC, _  = net.ParseMAC("ff:ee:dd:cc:bb:aa")
		etherLayer = &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ipLayer = &layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolTCP,
			Flags:    layers.IPv4DontFragment,
			DstIP:    net.IP{192, 168, 0, 20},
			TTL:      64,
			IHL:      5,
			Id:       1111,
		}
		tcpLayer = &layers.TCP{
			SrcPort: 12345,
			DstPort: 80,
			Seq:     111,
		}
	)
	tests := []struct {
		name          string
		srcIPAddrs    []net.IP
		bannedIPAddrs []net.IP
		wantCount     []uint32
	}{
		{
			name: "no drop",
			srcIPAddrs: []net.IP{
				net.IP{192, 168, 0, 10},
				net.IP{192, 168, 0, 11},
			},
			bannedIPAddrs: []net.IP{
				net.IP{192, 168, 10, 1},
			},
			wantCount: []uint32{
				0,
			},
		},
		{
			name: "drop 1",
			srcIPAddrs: []net.IP{
				net.IP{192, 168, 0, 10},
			},
			bannedIPAddrs: []net.IP{
				net.IP{192, 168, 0, 10},
				net.IP{192, 168, 0, 20},
			},
			wantCount: []uint32{
				1,
				0,
			},
		},
		{
			name: "drop many",
			srcIPAddrs: []net.IP{
				net.IP{192, 168, 0, 10},
				net.IP{192, 168, 0, 20},
				net.IP{192, 168, 0, 10},
				net.IP{192, 168, 0, 20},
				net.IP{192, 168, 0, 30},
			},
			bannedIPAddrs: []net.IP{
				net.IP{192, 168, 0, 10},
				net.IP{192, 168, 0, 20},
				net.IP{192, 168, 0, 30},
			},
			wantCount: []uint32{
				2,
				2,
				1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blMap, err := blacklist.NewBlacklist()
			assert.NoError(t, err)

			bpfProg := blMap.BPFProgram("xdp_prog_firewall")

			for _, bannedIPAddr := range tt.bannedIPAddrs {
				err := blMap.Set(bannedIPAddr)
				assert.NoError(t, err)
			}

			for _, srcIPAddr := range tt.srcIPAddrs {
				ip := ipLayer
				ip.SrcIP = srcIPAddr
				tcpLayer.SetNetworkLayerForChecksum(ip)

				pktBytes := testutil.SerializePacket(t,
					etherLayer,
					ipLayer,
					tcpLayer,
				)

				_, _, err := bpfProg.Test(pktBytes)
				assert.NoError(t, err)
			}

			for idx, bannedIPAddr := range tt.bannedIPAddrs {
				var (
					wantCount = tt.wantCount[idx]
				)
				gotCount, err := blMap.Get(bannedIPAddr)
				assert.NoError(t, err)

				assert.Equal(t, wantCount, gotCount)
			}

			blMap.Close()
		})
	}
}

func TestUnban(t *testing.T) {

}
