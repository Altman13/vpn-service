package vpn

import (
	"encoding/binary"
	"fmt"
	"net"
)

// allocateIP выбирает первый свободный адрес подсети для клиента.
//
// Адресация WireGuard-сервера: network — адрес сети, network+1 — шлюз
// (его занимает сам сервер), последний адрес — широковещательный.
// Клиентам выдаются адреса от network+2 до broadcast-1.
func allocateIP(cidr string, used map[string]struct{}) (string, error) {
	network, ones, err := parseIPv4Subnet(cidr)
	if err != nil {
		return "", err
	}

	size := uint32(1) << (32 - ones)
	if size < 4 {
		return "", fmt.Errorf("subnet %q is too small to hold vpn clients", cidr)
	}

	// offset 0 — адрес сети, offset 1 — шлюз, size-1 — broadcast.
	for offset := uint32(2); offset < size-1; offset++ {
		candidate := uint32ToIPv4(network + offset)
		if _, taken := used[candidate]; taken {
			continue
		}
		return candidate, nil
	}

	return "", fmt.Errorf("no free addresses left in subnet %q", cidr)
}

// parseIPv4Subnet возвращает адрес сети в виде uint32 и длину маски.
// Маска применяется принудительно, поэтому "10.0.0.1/24" и "10.0.0.0/24"
// дают одинаковый результат.
func parseIPv4Subnet(cidr string) (uint32, int, error) {
	if cidr == "" {
		return 0, 0, fmt.Errorf("vpn network cidr is not configured")
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid network cidr %q: %w", cidr, err)
	}

	ip := network.IP.To4()
	if ip == nil {
		return 0, 0, fmt.Errorf("only IPv4 subnets are supported, got %q", cidr)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return 0, 0, fmt.Errorf("invalid mask in %q", cidr)
	}

	return binary.BigEndian.Uint32(ip), ones, nil
}

func uint32ToIPv4(value uint32) string {
	return net.IPv4(
		byte(value>>24),
		byte(value>>16),
		byte(value>>8),
		byte(value),
	).String()
}
