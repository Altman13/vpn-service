package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	ServerAddress string         `mapstructure:"server_address"`
	LogLevel      string         `mapstructure:"log_level"`
	Database      DatabaseConfig `mapstructure:"database"`
	Redis         RedisConfig    `mapstructure:"redis"`
	JWT           JWTConfig      `mapstructure:"jwt"`
	Security      SecurityConfig `mapstructure:"security"`
	VPN           VPNConfig      `mapstructure:"vpn"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type JWTConfig struct {
	Secret string `mapstructure:"secret"`
	// ExpireTime — срок жизни access-токена в часах.
	ExpireTime int `mapstructure:"expire_time"`
	// RefreshExpireTime — срок жизни refresh-токена в часах.
	RefreshExpireTime int `mapstructure:"refresh_expire_time"`
}

// SecurityConfig описывает ограничения, не относящиеся к конкретному API.
type SecurityConfig struct {
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	CORS      CORSConfig      `mapstructure:"cors"`
}

type RateLimitConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// Requests — сколько запросов разрешено за окно.
	Requests int `mapstructure:"requests"`
	// WindowSeconds — длина окна в секундах.
	WindowSeconds int `mapstructure:"window_seconds"`
}

type CORSConfig struct {
	// AllowedOrigins — список разрешённых origin. Пустой список означает,
	// что CORS-заголовки не отдаются вовсе.
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

type VPNConfig struct {
	WireGuard WireGuardConfig `mapstructure:"wireguard"`
	OpenVPN   OpenVPNConfig   `mapstructure:"openvpn"`
}

type WireGuardConfig struct {
	InterfaceName string `mapstructure:"interface_name"`
	Port          int    `mapstructure:"port"`
	PrivateKey    string `mapstructure:"private_key"`
	PublicKey     string `mapstructure:"public_key"`
	NetworkCIDR   string `mapstructure:"network_cidr"`
	// Endpoint — адрес сервера, который попадает в клиентские конфиги.
	Endpoint string `mapstructure:"endpoint"`
	DNS      string `mapstructure:"dns"`
	// AllowedIPs — какие сети клиент гонит в туннель.
	AllowedIPs string `mapstructure:"allowed_ips"`
	// Enabled включает применение пиров к интерфейсу через wg.
	// false — сервис только выдаёт конфиги, интерфейсом управляют снаружи.
	Enabled bool `mapstructure:"enabled"`
}

type OpenVPNConfig struct {
	ConfigPath  string `mapstructure:"config_path"`
	Port        int    `mapstructure:"port"`
	NetworkCIDR string `mapstructure:"network_cidr"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	// env: jwt.secret -> JWT_SECRET, database.host -> DATABASE_HOST и т.д.
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	_ = viper.BindEnv("jwt.secret", "JWT_SECRET")
	_ = viper.BindEnv("database.host", "DATABASE_HOST")
	_ = viper.BindEnv("redis.host", "REDIS_HOST")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
