package main

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

type checkResult struct {
	ok     bool
	ms     int64
	err    string
	status string
}

const checkWorkers = 8

func checkNode(ctx context.Context, n *Node) checkResult {
	d := net.Dialer{Timeout: 5 * time.Second}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(n.Host, strconv.Itoa(n.Port)))
	if err != nil {
		return checkResult{err: shortErr(err)}
	}
	ms := time.Since(start).Milliseconds()
	if n.Security == "tls" || n.Security == "reality" || n.Security == "xtls" {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: orDefault(n.SNI, n.Host)})
		_ = tc.SetDeadline(time.Now().Add(6 * time.Second))
		if err := tc.Handshake(); err != nil {
			_ = tc.Close()
			return checkResult{err: "tls: " + shortErr(err)}
		}
		ms = time.Since(start).Milliseconds()
		_ = tc.Close()
	} else {
		_ = conn.Close()
	}
	return checkResult{ok: true, ms: ms}
}
