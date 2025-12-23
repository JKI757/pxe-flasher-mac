package logging

import (
	"fmt"
	"io"
	"sync"
	"time"
)

type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

func New(out io.Writer) *Logger {
	return &Logger{out: out}
}

func (l *Logger) Infof(format string, args ...any) {
	l.write("INFO", format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.write("ERROR", format, args...)
}

func (l *Logger) write(level, format string, args ...any) {
	if l == nil || l.out == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(l.out, "%s [%s] %s\n", timestamp, level, fmt.Sprintf(format, args...))
}
