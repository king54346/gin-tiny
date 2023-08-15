package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	lc := &net.ListenConfig{}
	if lc.MultipathTCP() {
		panic("MultipathTCP")
	}
	lc.SetMultipathTCP(true)
	listen, err := lc.Listen(context.Background(), "tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listen.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer conn.Close()
			isMultipathTcp, err := conn.(*net.TCPConn).MultipathTCP()
			if err != nil {
				panic(err)

			}
			fmt.Println(isMultipathTcp)
			for {
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					if errors.Is(err, io.EOF) {
						return
					}
					panic(err)
				}
				fmt.Println(string(buf[:n]))
				_, err = conn.Write(buf[:n])
				if err != nil {
					panic(err)
				}
			}
		}()
	}
}

func TestClient(t *testing.T) {
	conn := &net.Dialer{}

	if conn.MultipathTCP() {
		panic("MultipathTCP")
	}
	conn.SetMultipathTCP(true)
	tcpConn, err := conn.Dial("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}

	isMultipathTcp, err := tcpConn.(*net.TCPConn).MultipathTCP()
	if err != nil {
		panic(err)
	}
	fmt.Println(isMultipathTcp)
	for {
		snt := []byte("hello")
		_, err := tcpConn.Write(snt)
		if err != nil {
			panic(err)
		}
		bytes := make([]byte, len(snt))
		_, err = tcpConn.Read(bytes)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(bytes))
		time.Sleep(time.Second)
	}
}
