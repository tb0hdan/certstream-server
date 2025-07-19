package configs

import (
	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	CTLogs  CTLogsConfig  `mapstructure:"ct_logs"`
	Logging LoggingConfig `mapstructure:"logging"`
	// Version information
	Version string
	Commit  string
	Date    string
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port             int    `mapstructure:"port"`
	Host             string `mapstructure:"host"`
	ReadTimeout      int    `mapstructure:"read_timeout"`
	WriteTimeout     int    `mapstructure:"write_timeout"`
	MaxMessageSize   int64  `mapstructure:"max_message_size"`
	PongTimeout      int    `mapstructure:"pong_timeout"`
	PingPeriod       int    `mapstructure:"ping_period"`
	ClientBufferSize int    `mapstructure:"client_buffer_size"`
}

// CTLogsConfig holds CT logs configuration
type CTLogsConfig struct {
	LogListURL      string `mapstructure:"log_list_url"`
	UserAgent       string `mapstructure:"user_agent"`
	PollingInterval int    `mapstructure:"polling_interval"`
	BatchSize       int    `mapstructure:"batch_size"`
	MaxConcurrency  int    `mapstructure:"max_concurrency"`
	RequestTimeout  int    `mapstructure:"request_timeout"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// LoadConfig loads configuration from file and environment
func LoadConfig(configPath, version, commit, date string) (*Config, error) {
	// If a specific config file path is provided, use it
	if len(configPath) > 0 && configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath(".")
	}

	// Set defaults
	viper.SetDefault("server.port", 4000)
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", 10)
	viper.SetDefault("server.write_timeout", 10)
	viper.SetDefault("server.max_message_size", 512000)
	viper.SetDefault("server.pong_timeout", 60)
	viper.SetDefault("server.ping_period", 30)
	viper.SetDefault("server.client_buffer_size", 500)

	viper.SetDefault("ct_logs.log_list_url", "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json")
	viper.SetDefault("ct_logs.user_agent", "certstream-server-go/1.0")
	viper.SetDefault("ct_logs.polling_interval", 10)
	viper.SetDefault("ct_logs.batch_size", 512)
	viper.SetDefault("ct_logs.max_concurrency", 5)
	viper.SetDefault("ct_logs.request_timeout", 30)

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")

	// Read environment variables
	viper.SetEnvPrefix("CERTSTREAM")
	viper.AutomaticEnv()

	// Allow PORT env variable to override server.port
	if port := viper.GetInt("PORT"); port != 0 {
		viper.Set("server.port", port)
	}

	// Read config file if exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}
	// Set version information
	config.Version = version
	config.Commit = commit
	config.Date = date

	return &config, nil
}
