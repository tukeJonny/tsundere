package main

import (
	"context"
	"fmt"

	"github.com/tukejonny/tsundere/pb"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
)

var (
	ip         string
	serverAddr string
	serverPort int
)

var ban = cli.Command{
	Name:      "ban",
	Aliases:   []string{"b"},
	Usage:     "ban ip",
	ArgsUsage: " ",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:        "ip, i",
			Destination: &ip,
			Required:    true,
		},
		cli.StringFlag{
			Name:        "addr, a",
			Destination: &serverAddr,
			Value:       "127.0.0.1",
		},
		cli.IntFlag{
			Name:        "port, p",
			Destination: &serverPort,
			Value:       8080,
		},
	},
	Action: func(cliCtx *cli.Context) error {
		ctx := context.Background()

		addr := fmt.Sprintf("%s:%d", serverAddr, serverPort)
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			return cli.NewExitError(err, 1)
		}
		defer conn.Close()

		client := pb.NewFirewallClient(conn)
		if _, err := client.Ban(ctx, &pb.BanRequest{Ip: ip}); err != nil {
			return cli.NewExitError(err, 1)
		}

		return nil
	},
}
