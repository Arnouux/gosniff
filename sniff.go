package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"sync"
	"net"
	"time"
	"strings"
	"strconv"
    "math"
)

var (
	localIP = GetOutboundIP()
	batchInterval = 2 * time.Second
	nbBatches = 20
)

func GetOutboundIP() []byte {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        return []byte{0,0,0,0}
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
	octets := strings.Split(localAddr.IP.String(), ".")

	octet0, _ := strconv.Atoi(octets[0])
	octet1, _ := strconv.Atoi(octets[1])
	octet2, _ := strconv.Atoi(octets[2])
	octet3, _ := strconv.Atoi(octets[3])

	b := []byte{byte(octet0),byte(octet1),byte(octet2),byte(octet3)}

    return b
}

func adressSlicesEqual(addr1 []byte, addr2 []byte) bool {
	if len(addr1) != len(addr2) {
        return false
    }
    for i := range addr1 {
        if addr1[i] != addr2[i] {
            return false
        }
    }
    return true
}

func listenDevice(device pcap.Interface) {
	fmt.Printf("Device Name: %s\n", device.Name)
	fmt.Printf("Device Description: %s\n", device.Description)
	fmt.Printf("Device Flags: %d\n", device.Flags)

	handle, err := pcap.OpenLive(device.Name, 1024, false, 5)
	if err != nil {
		fmt.Println("error openLive")
		return
	}
	defer handle.Close()
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    start := time.Now()
	inPackets := make([]int, nbBatches)
	outPackets := make([]int, nbBatches)
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil { // for example ARP packets do not have Network layer
			continue
		}

		netFlow := packet.NetworkLayer().NetworkFlow()
		src, dst := netFlow.Endpoints()
		//fmt.Println(device.Name + " : " + src.String() + " -> " + dst.String())
		if dst.String() == "239.255.255.250" {
				fmt.Println("SSDP")
		}
		batch := int(math.Mod(time.Since(start).Seconds() / batchInterval.Seconds(), float64(nbBatches)))
		if adressSlicesEqual(dst.Raw(), localIP) {
			inPackets[batch]++
			fmt.Printf("%v\n", inPackets)
		} else if adressSlicesEqual(src.Raw(), localIP) {
			outPackets[batch]++
			fmt.Printf("%v\n", outPackets)
		}
	}
}

func main() {
	fmt.Println("hi")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("error")
		return
	}

	var wg sync.WaitGroup
	for _, device := range devices {
		wg.Add(1)
		go func(device pcap.Interface) {
			defer wg.Done()
			listenDevice(device)
		}(device)
	}
	wg.Wait()
}