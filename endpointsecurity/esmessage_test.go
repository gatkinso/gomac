package endpointsecurity

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestEs_message_size(t *testing.T) {
	var msg = new(Es_message_t)
	res := Es_message_size(msg)

	fmt.Printf("Es_message_t size: %d\n", res)

	if res == 0 {
		t.Fatalf("TestEs_message_size failed!")
	}
}

func TestEs_copy_message(t *testing.T) {
	var lhs = Es_message_t{
		version:        1,
		time:           time.Now(),
		mach_time:      2,
		deadline:       3,
		process:        nil,
		seq_num:        4,
		action_type:    nil,
		event_type:     ES_EVENT_TYPE_AUTH_EXEC,
		event:          nil,
		thread:         nil,
		global_seq_num: 5,
	}

	rhs := Es_copy_message(&lhs)

	res := reflect.DeepEqual(lhs, *rhs)
	if !res {
		t.Fatalf("TestEs_copy_message failed!")
	}
}

func TestEs_free_message(t *testing.T) {

}

func TestEs_retain_message(t *testing.T) {

}

func TestEs_release_message(t *testing.T) {

}

func TestEs_exec_arg_count(t *testing.T) {

}

func TestEs_exec_env_count(t *testing.T) {

}

func TestEs_exec_fd_count(t *testing.T) {

}

func TestEs_exec_arg(t *testing.T) {

}

func TestEs_exec_env(t *testing.T) {

}

func TestEs_exec_fd(t *testing.T) {

}
