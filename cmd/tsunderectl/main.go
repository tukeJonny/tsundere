package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
)

func main() {
	os.Exit(cliMain())
}

func cliMain() int {
	app := cli.NewApp()
	app.Name = "tsunderectl"
	app.Usage = "controller CLI for tsundere firewall app"
	app.Description = ""
	app.Authors = []cli.Author{
		{
			Name:  "tukeJonny",
			Email: "ne250143@yahoo.co.jp",
		},
	}
	app.HelpName = "tsunderectl"

	app.Commands = []cli.Command{
		list,
		ban,
		unban,
	}

	app.Action = func(ctx *cli.Context) error {

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Println(err.Error())
		return 1
	}

	return 0
}
