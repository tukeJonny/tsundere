package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/tukejonny/tsundere/service"
	"github.com/urfave/cli"
)

var (
	listenAddr string
	listenPort int
)

func main() {
	os.Exit(cliMain())
}

func cliMain() int {
	app := cli.NewApp()
	app.Name = "tsundered"
	app.Usage = "a simple dynamic firewall"
	app.Description = ""
	app.Authors = []cli.Author{
		{
			Name:  "tukeJonny",
			Email: "ne250143@yahoo.co.jp",
		},
	}
	app.HelpName = "tsundered"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "addr, a",
			Value:       "127.0.0.1",
			EnvVar:      "TSUNDERED_LISTEN_ADDR",
			Destination: &listenAddr,
		},
		cli.IntFlag{
			Name:        "port, p",
			Value:       8080,
			EnvVar:      "TSUNDERED_LISTEN_PORT",
			Destination: &listenPort,
		},
	}
	app.Action = func(ctx *cli.Context) error {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
		defer close(sigCh)

		addr := fmt.Sprintf("%s:%d", listenAddr, listenPort)
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			return cli.NewExitError(err, 1)
		}

		tsundereServer, err := service.NewTsundereService()
		if err != nil {
			return cli.NewExitError(err, 1)
		}

		errCh := make(chan error, 1)
		go func() {
			defer close(errCh)
			errCh <- tsundereServer.Serve(lis)
		}()

		select {
		case err := <-errCh:
			return cli.NewExitError(err, 1)
		case sig := <-sigCh:
			log.Printf("receive signal: %s", sig)
			return nil
		}
	}

	if err := app.Run(os.Args); err != nil {
		log.Println(err.Error())
		return 1
	}

	return 0
}
