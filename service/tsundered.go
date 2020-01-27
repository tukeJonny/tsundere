package service

import (
	"context"
	"errors"
	"net"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"

	"github.com/tukejonny/tsundere/bpf/blacklist"
	"github.com/tukejonny/tsundere/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

var (
	ErrInvalidIP = errors.New("invalid ip address")
)

type Tsundere struct {
	blacklist *blacklist.Blacklist
}

func NewTsundereService() (*grpc.Server, error) {
	grpcServer := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_recovery.UnaryServerInterceptor(),
		),
	)

	blacklist, err := blacklist.NewBlacklist()
	if err != nil {
		return nil, err
	}

	svc := &Tsundere{
		blacklist: blacklist,
	}

	pb.RegisterFirewallServer(grpcServer, svc)
	reflection.Register(grpcServer)

	return grpcServer, nil
}

func (t *Tsundere) Ban(ctx context.Context, req *pb.BanRequest) (*pb.BanResponse, error) {
	ip := net.ParseIP(req.GetIp())
	if ip == nil {
		return nil, status.Errorf(codes.InvalidArgument, ErrInvalidIP.Error())
	}

	if err := t.blacklist.Set(ip); err != nil {
		return nil, status.Errorf(codes.Aborted, err.Error())
	}

	return &pb.BanResponse{}, nil
}

func (t *Tsundere) Unban(ctx context.Context, req *pb.UnbanRequest) (*pb.UnbanResponse, error) {
	ip := net.ParseIP(req.GetIp())
	if ip == nil {
		return nil, status.Errorf(codes.InvalidArgument, ErrInvalidIP.Error())
	}

	if err := t.blacklist.Delete(ip); err != nil {
		return nil, status.Errorf(codes.Aborted, err.Error())
	}

	return &pb.UnbanResponse{}, nil
}

func (t *Tsundere) ListBanned(ctx context.Context, req *pb.ListBannedRequest) (*pb.ListBannedResponse, error) {
	banned, err := t.blacklist.List()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return &pb.ListBannedResponse{
		Ip: banned,
	}, nil
}
