package controller

import (
	"github.com/scroll-tech/paymaster/internal/config"
)

// PaymasterCtl the paymaster controller
var PaymasterCtl *PaymasterController

// InitAPI init the api controller
func InitAPI(cfg *config.Config) {
	PaymasterCtl = NewPaymasterController(cfg)
}
