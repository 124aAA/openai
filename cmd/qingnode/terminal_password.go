package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type terminalSignalError struct{ signal os.Signal }

func (e terminalSignalError) Error() string {
	return fmt.Sprintf("口令输入已中断（%s）；终端状态已恢复", e.signal)
}

// Only intercept signals while echo is disabled. Long-running probes retain
// their own context cancellation and process cleanup rather than exiting here.
func readTerminalPassword(fd int) (password []byte, err error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer func() {
		if restore := term.Restore(fd, state); restore != nil {
			if err == nil {
				err = fmt.Errorf("终端恢复失败：%v", restore)
			} else {
				err = fmt.Errorf("%w；终端恢复失败：%v", err, restore)
			}
		}
		signal.Stop(interrupt)
	}()
	settings, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	settings.Lflag = settings.Lflag&^unix.ECHO | unix.ICANON | unix.ISIG
	if err = unix.IoctlSetTermios(fd, unix.TCSETS, settings); err != nil {
		return nil, err
	}
	// Poll synchronously: no blocked reader goroutine can later disable echo
	// again after our cancellation path restored the original terminal state.
	var value []byte
	chunk := make([]byte, 4096)
	for {
		select {
		case sig := <-interrupt:
			return nil, terminalSignalError{sig}
		default:
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP}}
		if _, err = unix.Poll(fds, 100); errors.Is(err, unix.EINTR) {
			continue
		} else if err != nil {
			return nil, err
		}
		if fds[0].Revents == 0 {
			continue
		}
		n, err := unix.Read(fd, chunk)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.EOF
		}
		for _, b := range chunk[:n] {
			if b == '\n' || b == '\r' {
				return value, nil
			}
			value = append(value, b)
			if len(value) > 4096 {
				return nil, errors.New("口令最多4096字节；本次未应用")
			}
		}
	}
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var e terminalSignalError
	if errors.As(err, &e) {
		if e.signal == syscall.SIGTERM {
			return 143
		}
		return 130
	}
	return 1
}
