package main

import (
	"context"
	"fmt"

	"github.com/tukejonny/tsundere/pb"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
)

var list = cli.Command{
	Name:      "list",
	Aliases:   []string{"l"},
	Usage:     "list blacklist entries",
	ArgsUsage: " ",
	Flags: []cli.Flag{
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
		resp, err := client.ListBanned(ctx, &pb.ListBannedRequest{})
		if err != nil {
			return cli.NewExitError(err, 1)
		}

		entries := resp.GetIp()
		fmt.Println("===== Blacklist =====")
		for ip, cnt := range entries {
			fmt.Printf("\t- %s: %d dropped", ip, cnt)
		}

		return nil
	},
}
