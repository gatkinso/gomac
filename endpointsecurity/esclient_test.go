package endpointsecurity

import (
	"fmt"
	"testing"
)

func TestEs_subscribe(t *testing.T) {
}

func TestEs_unsubscribe(t *testing.T) {
}

func TestEs_unsubscribe_all(t *testing.T) {
}

func TestEs_subscriptions(t *testing.T) {
}

func TestEs_respond_auth_result(t *testing.T) {
}

func TestEs_respond_flags_result(t *testing.T) {
}

func TestEs_mute_process(t *testing.T) {
}

func TestEs_mute_process_events(t *testing.T) {
}

func TestEs_unmute_process(t *testing.T) {
}

func TestEs_unmute_process_events(t *testing.T) {
}

func TestEs_muted_processes(t *testing.T) {
}

func TestEs_muted_processes_events(t *testing.T) {
}

func TestEs_release_muted_processes(t *testing.T) {
}

func TestEs_mute_path(t *testing.T) {
}

func TestEs_mute_path_events(t *testing.T) {
}

func TestEs_mute_path_prefix(t *testing.T) {
}

func TestEs_mute_path_literal(t *testing.T) {
}

func TestEs_unmute_all_paths(t *testing.T) {
}

func TestEs_unmute_all_target_paths(t *testing.T) {
}

func TestEs_unmute_path(t *testing.T) {
}

func TestEs_unmute_path_events(t *testing.T) {
}

func TestEs_muted_paths_events(t *testing.T) {
}

func TestEs_release_muted_paths(t *testing.T) {
}

func TestEs_invert_muting(t *testing.T) {
}

func TestEs_muting_inverted(t *testing.T) {
}

func TestEs_clear_cache(t *testing.T) {
}

func blockHandler() {
	fmt.Printf("Called Block handler!\n")
}

func TestEs_new_client(t *testing.T) {

	handler := blockHandler
	var client_ptr = new(Es_client_t)

	res := Es_new_client(&client_ptr, handler)

	if res != ES_RETURN_SUCCESS {
		t.Fatalf("TestEs_new_client failed!")
	}
}

func TestEs_delete_client(t *testing.T) {

	var client_ptr = new(Es_client_t)

	res := Es_delete_client(client_ptr)

	if res != ES_RETURN_SUCCESS {
		t.Fatalf("TestEs_new_client failed!")
	}
}
