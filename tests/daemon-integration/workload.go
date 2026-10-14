// Tiny disposable CI workload; no Harbor data, credentials or external image.
package main

import (
    "io"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"
)

func main() {
    if len(os.Args) > 1 && os.Args[1] == "health" {
        c, err := net.DialTimeout("tcp", "127.0.0.1:8000", time.Second)
        if err != nil { os.Exit(1) }
        c.Close()
        return
    }
    port := ":8000"
    if len(os.Args) > 1 && os.Args[1] == "log" {
        l, err := net.Listen("tcp", ":1514")
        if err != nil { panic(err) }
        go func() {
            for { c, err := l.Accept(); if err != nil { return }
                go func() { io.Copy(io.Discard, c); c.Close() }()
            }
        }()
    }
    l, err := net.Listen("tcp", port)
    if err != nil { panic(err) }
    go func() { for { c, err := l.Accept(); if err != nil { return }; c.Close() } }()
    done := make(chan os.Signal, 1)
    signal.Notify(done, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
    <-done
    l.Close()
}

