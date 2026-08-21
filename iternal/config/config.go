package config

import (
    "github.com/spf13/viper"
)

type Config struct {
    ServerAddress string `mapstructure:"server_address"`
    LogLevel      string `mapstructure:"log_level"`
    Database      DatabaseConfig
    Redis         RedisConfig
    JWT           JWTConfig
    VPN           VPNConfig
}

type DatabaseConfig struct {
    Host     string
    Port     int
    User     string
    Password string
    DBName   string
    SSLMode  string
}

type RedisConfig struct {
    Host     string
    Port     int
    Password string
    DB       int
}

type JWTConfig struct {
    Secret     string
    ExpireTime int // hours
}

type VPNConfig struct {
    WireGuard WireGuardConfig
    OpenVPN   OpenVPNConfig
}

type WireGuardConfig struct {
    InterfaceName string
    Port          int
    PrivateKey    string
    PublicKey     string
    NetworkCIDR   string
}

type OpenVPNConfig struct {
    ConfigPath string
    Port       int
    NetworkCIDR string
}

func Load() (*Config, error) {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath("./configs")
    viper.AddConfigPath(".")

    // Переменные окружения
    viper.AutomaticEnv()

    if err := viper.ReadInConfig(); err != nil {
        return nil, err
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, err
    }

    return &config, nil
}