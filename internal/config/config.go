package config

import (
	"github.com/go-redis/redis/v9"
	"github.com/pusher/pusher-http-go/v5"
)

type LocalApiConfig struct {
	DB           *database.Queries
	RedisClient  *redis.Client
	PusherClient *pusher.Client
}
