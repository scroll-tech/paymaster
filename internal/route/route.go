package route

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/controller"
	"github.com/scroll-tech/paymaster/internal/middleware"
	"github.com/scroll-tech/paymaster/internal/utils/observability"
)

// Route register route for coordinator
func Route(router *gin.Engine, conf *config.Config) {
	router.Use(gin.Recovery())

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	observability.Use(router, "paymaster", prometheus.DefaultRegisterer)

	rootGroup := router.Group("")

	registerRootRoutes(rootGroup, conf)
}

func registerRootRoutes(rootGroup *gin.RouterGroup, conf *config.Config) {
	rootGroup.POST("/", middleware.AuthMiddleware(conf), middleware.RateLimiter(conf), controller.PaymasterCtl.Paymaster)
}
