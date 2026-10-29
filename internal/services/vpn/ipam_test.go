package vpn

import (
	"fmt"
	"testing"
)

func addressSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func TestAllocateIP(t *testing.T) {
	cases := []struct {
		name    string
		cidr    string
		used    map[string]struct{}
		want    string
		wantErr bool
	}{
		{
			name: "первый клиентский адрес",
			cidr: "10.0.0.0/24",
			want: "10.0.0.2",
		},
		{
			name: "первый адрес занят",
			cidr: "10.0.0.0/24",
			used: addressSet("10.0.0.2"),
			want: "10.0.0.3",
		},
		{
			name: "занятые адреса пропускаются",
			cidr: "10.0.0.0/24",
			used: addressSet("10.0.0.2", "10.0.0.3", "10.0.0.5"),
			want: "10.0.0.4",
		},
		{
			name: "адрес сети и шлюз не выдаются",
			cidr: "10.0.0.0/30",
			want: "10.0.0.2",
		},
		{
			name: "хостовая часть маски игнорируется",
			cidr: "10.0.0.1/24",
			want: "10.0.0.2",
		},
		{
			name:    "нехватка адресов в /30",
			cidr:    "10.0.0.0/30",
			used:    addressSet("10.0.0.2"),
			wantErr: true,
		},
		{
			name:    "слишком маленькая подсеть",
			cidr:    "10.0.0.0/31",
			wantErr: true,
		},
		{
			name:    "пустой cidr",
			cidr:    "",
			wantErr: true,
		},
		{
			name:    "не cidr",
			cidr:    "не-подсеть",
			wantErr: true,
		},
		{
			name:    "IPv6 не поддерживается",
			cidr:    "fd00::/64",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := allocateIP(tc.cidr, tc.used)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("ожидалась ошибка, получен адрес %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
			if got != tc.want {
				t.Fatalf("получен %q, ожидался %q", got, tc.want)
			}
		})
	}
}

// /24 отдаёт 253 адреса (.2–.254), после чего обязан сообщить об исчерпании.
func TestAllocateIPExhaustsSubnet(t *testing.T) {
	used := make(map[string]struct{})
	for last := 2; last <= 254; last++ {
		used[fmt.Sprintf("10.0.0.%d", last)] = struct{}{}
	}

	if address, err := allocateIP("10.0.0.0/24", used); err == nil {
		t.Fatalf("адреса закончились, но выдан %q", address)
	}
}

func TestAllocateIPNeverReturnsGatewayOrBroadcast(t *testing.T) {
	subnet := "10.0.0.0/24"
	used := make(map[string]struct{})

	for {
		address, err := allocateIP(subnet, used)
		if err != nil {
			break
		}
		if address == "10.0.0.0" || address == "10.0.0.1" || address == "10.0.0.255" {
			t.Fatalf("выдан служебный адрес %s", address)
		}
		used[address] = struct{}{}
	}

	if len(used) != 253 {
		t.Fatalf("выдано %d адресов, ожидалось 253", len(used))
	}
}
