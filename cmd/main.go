package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/scroll-tech/go-ethereum/log"
	"github.com/urfave/cli/v2"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/controller"
	"github.com/scroll-tech/paymaster/internal/route"
	"github.com/scroll-tech/paymaster/internal/utils"
	"github.com/scroll-tech/paymaster/internal/utils/observability"
)

func action(ctx *cli.Context) error {
	// Load config file.
	cfgFile := ctx.String(utils.ConfigFileFlag.Name)
	cfg, err := config.NewConfig(cfgFile)
	if err != nil {
		log.Crit("failed to load config file", "config file", cfgFile, "error", err)
	}

	observability.Server(ctx)

	router := gin.New()
	controller.InitAPI(cfg)
	route.Route(router, cfg)
	port := ctx.String(utils.HTTPPortFlag.Name)
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if runServerErr := srv.ListenAndServe(); runServerErr != nil && !errors.Is(runServerErr, http.ErrServerClosed) {
			log.Crit("run coordinator http server failure", "error", runServerErr)
		}
	}()

	log.Info("Start paymaster success...", "version", utils.Version)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	<-interrupt

	log.Info("Start shutdown paymaster server...")

	closeCtx, cancelExit := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelExit()
	if err = srv.Shutdown(closeCtx); err != nil {
		log.Warn("shutdown paymaster server failure", "error", err)
		return nil
	}

	<-closeCtx.Done()
	log.Info("paymaster server exiting success")
	return nil
}

// Run event watcher cmd instance.
func main() {
	app := cli.NewApp()
	app.Action = action
	app.Name = "api"
	app.Usage = "The Scroll paymaster"
	app.Version = utils.Version
	app.Flags = append(app.Flags, utils.CommonFlags...)
	app.Commands = []*cli.Command{}
	app.Before = func(ctx *cli.Context) error {
		return utils.LogSetup(ctx)
	}

	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
