//go:build windows

package artifact

import (
	"errors"
	"os"
	"os/exec"
)

// Windows has no execve(2): a process cannot replace its own image. syscall.Exec
// exists only as a stub that returns EWINDOWS. So on Windows Exec spawns the
// target as a child with our stdio inherited, waits for it, and then exits the
// parent with the child's exit code — the closest faithful analogue of exec's
// "become the target program" contract. It returns (rather than exiting) only
// when the child could not be started at all, so the caller can report the
// error like any other failure.
func init() { Exec = execWindows }

func execWindows(argv0 string, argv []string, env []string) error {
	var args []string
	if len(argv) > 1 {
		args = argv[1:]
	}
	cmd := exec.Command(argv0, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		os.Exit(0)
	}
	// The child ran but exited non-zero: propagate its exact code.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	// Could not start the process (bad path, permission, …): report it.
	return err
}
