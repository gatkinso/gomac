package endpointsecurity

import "bytes"

type audit_token_t struct {
	val [8]uint32
}

type Es_action_type_t int

const (
	ES_ACTION_TYPE_AUTH Es_action_type_t = iota
	ES_ACTION_TYPE_NOTIFY
)

type Es_set_or_clear_t int

const (
	ES_SET Es_set_or_clear_t = iota
	ES_CLEAR
)

/*
 * This enum describes the type of the Es_event_proc_check_t event that are currently used
 *
 * ES_PROC_CHECK_TYPE_KERNMSGBUF  ES_PROC_CHECK_TYPE_TERMINATE and
 * ES_PROC_CHECK_TYPE_UDATA_INFO are deprecated and no proc_check messages will be generated
 * for the corresponding proc_info call numbers.
 * The terminate callnum is covered by the signal event.
 */
type Es_proc_check_type_t int

const (
	ES_PROC_CHECK_TYPE_LISTPIDS        Es_proc_check_type_t = 0x1
	ES_PROC_CHECK_TYPE_PIDINFO         Es_proc_check_type_t = 0x2
	ES_PROC_CHECK_TYPE_PIDFDINFO       Es_proc_check_type_t = 0x3
	ES_PROC_CHECK_TYPE_KERNMSGBUF      Es_proc_check_type_t = 0x4 // deprecated  not generated
	ES_PROC_CHECK_TYPE_SETCONTROL      Es_proc_check_type_t = 0x5
	ES_PROC_CHECK_TYPE_PIDFILEPORTINFO Es_proc_check_type_t = 0x6
	ES_PROC_CHECK_TYPE_TERMINATE       Es_proc_check_type_t = 0x7 // deprecated  not generated
	ES_PROC_CHECK_TYPE_DIRTYCONTROL    Es_proc_check_type_t = 0x8
	ES_PROC_CHECK_TYPE_PIDRUSAGE       Es_proc_check_type_t = 0x9
	ES_PROC_CHECK_TYPE_UDATA_INFOv     Es_proc_check_type_t = 0xe // deprecated  not generated
)

/*
 * This enum describes the types of XPC service domains.
 */
type Es_xpc_domain_type_t int

const (
	ES_XPC_DOMAIN_TYPE_SYSTEM Es_xpc_domain_type_t = iota + 1
	ES_XPC_DOMAIN_TYPE_USER
	ES_XPC_DOMAIN_TYPE_USER_LOGIN
	ES_XPC_DOMAIN_TYPE_SESSION
	ES_XPC_DOMAIN_TYPE_PID
	ES_XPC_DOMAIN_TYPE_MANAGER
	ES_XPC_DOMAIN_TYPE_PORT
	ES_XPC_DOMAIN_TYPE_GUI
)

/*
 * This enum describes the types of authentications that
 * ES_EVENT_TYPE_NOTIFY_AUTHENTICATION can describe.
 */
type Es_authentication_type_t int

const (
	ES_AUTHENTICATION_TYPE_OD Es_authentication_type_t = iota
	ES_AUTHENTICATION_TYPE_TOUCHID
	ES_AUTHENTICATION_TYPE_TOKEN
	ES_AUTHENTICATION_TYPE_AUTO_UNLOCK
	// ES_AUTHENTICATION_TYPE_LAST is not a valid type of authentication
	// but is a convenience value to operate on the range of defined
	// authentication types.
	ES_AUTHENTICATION_TYPE_LAST
)

/*
 * The valid event types recognized by EndpointSecurity
 *
 * When a program subscribes to and receives an AUTH-related event  it must respond
 * with an appropriate result indicating whether or not the operation should be allowed to continue.
 * The valid API options are:
 * - Es_respond_auth_result
 * - Es_respond_flags_result
 *
 * Currently  only ES_EVENT_TYPE_AUTH_OPEN must use Es_respond_flags_result. All other AUTH events
 * must use Es_respond_auth_result.
 */
type Es_event_type_t int

const (
	// The following events are available beginning in macOS 10.15
	ES_EVENT_TYPE_AUTH_EXEC Es_event_type_t = iota
	ES_EVENT_TYPE_AUTH_OPEN
	ES_EVENT_TYPE_AUTH_KEXTLOAD
	ES_EVENT_TYPE_AUTH_MMAP
	ES_EVENT_TYPE_AUTH_MPROTECT
	ES_EVENT_TYPE_AUTH_MOUNT
	ES_EVENT_TYPE_AUTH_RENAME
	ES_EVENT_TYPE_AUTH_SIGNAL
	ES_EVENT_TYPE_AUTH_UNLINK
	ES_EVENT_TYPE_NOTIFY_EXEC
	ES_EVENT_TYPE_NOTIFY_OPEN
	ES_EVENT_TYPE_NOTIFY_FORK
	ES_EVENT_TYPE_NOTIFY_CLOSE
	ES_EVENT_TYPE_NOTIFY_CREATE
	ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA
	ES_EVENT_TYPE_NOTIFY_EXIT
	ES_EVENT_TYPE_NOTIFY_GET_TASK
	ES_EVENT_TYPE_NOTIFY_KEXTLOAD
	ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD
	ES_EVENT_TYPE_NOTIFY_LINK
	ES_EVENT_TYPE_NOTIFY_MMAP
	ES_EVENT_TYPE_NOTIFY_MPROTECT
	ES_EVENT_TYPE_NOTIFY_MOUNT
	ES_EVENT_TYPE_NOTIFY_UNMOUNT
	ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN
	ES_EVENT_TYPE_NOTIFY_RENAME
	ES_EVENT_TYPE_NOTIFY_SETATTRLIST
	ES_EVENT_TYPE_NOTIFY_SETEXTATTR
	ES_EVENT_TYPE_NOTIFY_SETFLAGS
	ES_EVENT_TYPE_NOTIFY_SETMODE
	ES_EVENT_TYPE_NOTIFY_SETOWNER
	ES_EVENT_TYPE_NOTIFY_SIGNAL
	ES_EVENT_TYPE_NOTIFY_UNLINK
	ES_EVENT_TYPE_NOTIFY_WRITE
	ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE
	ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE
	ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE
	ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE
	ES_EVENT_TYPE_AUTH_READLINK
	ES_EVENT_TYPE_NOTIFY_READLINK
	ES_EVENT_TYPE_AUTH_TRUNCATE
	ES_EVENT_TYPE_NOTIFY_TRUNCATE
	ES_EVENT_TYPE_AUTH_LINK
	ES_EVENT_TYPE_NOTIFY_LOOKUP
	ES_EVENT_TYPE_AUTH_CREATE
	ES_EVENT_TYPE_AUTH_SETATTRLIST
	ES_EVENT_TYPE_AUTH_SETEXTATTR
	ES_EVENT_TYPE_AUTH_SETFLAGS
	ES_EVENT_TYPE_AUTH_SETMODE
	ES_EVENT_TYPE_AUTH_SETOWNER
	// The following events are available beginning in macOS 10.15.1
	ES_EVENT_TYPE_AUTH_CHDIR
	ES_EVENT_TYPE_NOTIFY_CHDIR
	ES_EVENT_TYPE_AUTH_GETATTRLIST
	ES_EVENT_TYPE_NOTIFY_GETATTRLIST
	ES_EVENT_TYPE_NOTIFY_STAT
	ES_EVENT_TYPE_NOTIFY_ACCESS
	ES_EVENT_TYPE_AUTH_CHROOT
	ES_EVENT_TYPE_NOTIFY_CHROOT
	ES_EVENT_TYPE_AUTH_UTIMES
	ES_EVENT_TYPE_NOTIFY_UTIMES
	ES_EVENT_TYPE_AUTH_CLONE
	ES_EVENT_TYPE_NOTIFY_CLONE
	ES_EVENT_TYPE_NOTIFY_FCNTL
	ES_EVENT_TYPE_AUTH_GETEXTATTR
	ES_EVENT_TYPE_NOTIFY_GETEXTATTR
	ES_EVENT_TYPE_AUTH_LISTEXTATTR
	ES_EVENT_TYPE_NOTIFY_LISTEXTATTR
	ES_EVENT_TYPE_AUTH_READDIR
	ES_EVENT_TYPE_NOTIFY_READDIR
	ES_EVENT_TYPE_AUTH_DELETEEXTATTR
	ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR
	ES_EVENT_TYPE_AUTH_FSGETPATH
	ES_EVENT_TYPE_NOTIFY_FSGETPATH
	ES_EVENT_TYPE_NOTIFY_DUP
	ES_EVENT_TYPE_AUTH_SETTIME
	ES_EVENT_TYPE_NOTIFY_SETTIME
	ES_EVENT_TYPE_NOTIFY_UIPC_BIND
	ES_EVENT_TYPE_AUTH_UIPC_BIND
	ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT
	ES_EVENT_TYPE_AUTH_UIPC_CONNECT
	ES_EVENT_TYPE_AUTH_EXCHANGEDATA
	ES_EVENT_TYPE_AUTH_SETACL
	ES_EVENT_TYPE_NOTIFY_SETACL
	// The following events are available beginning in macOS 10.15.4
	ES_EVENT_TYPE_NOTIFY_PTY_GRANT
	ES_EVENT_TYPE_NOTIFY_PTY_CLOSE
	ES_EVENT_TYPE_AUTH_PROC_CHECK
	ES_EVENT_TYPE_NOTIFY_PROC_CHECK
	ES_EVENT_TYPE_AUTH_GET_TASK
	// The following events are available beginning in macOS 11.0
	ES_EVENT_TYPE_AUTH_SEARCHFS
	ES_EVENT_TYPE_NOTIFY_SEARCHFS
	ES_EVENT_TYPE_AUTH_FCNTL
	ES_EVENT_TYPE_AUTH_IOKIT_OPEN
	ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME
	ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME
	ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
	ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME
	ES_EVENT_TYPE_NOTIFY_TRACE
	ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
	ES_EVENT_TYPE_AUTH_REMOUNT
	ES_EVENT_TYPE_NOTIFY_REMOUNT
	// The following events are available beginning in macOS 11.3
	ES_EVENT_TYPE_AUTH_GET_TASK_READ
	ES_EVENT_TYPE_NOTIFY_GET_TASK_READ
	ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT
	// The following events are available beginning in macOS 12.0
	ES_EVENT_TYPE_NOTIFY_SETUID
	ES_EVENT_TYPE_NOTIFY_SETGID
	ES_EVENT_TYPE_NOTIFY_SETEUID
	ES_EVENT_TYPE_NOTIFY_SETEGID
	ES_EVENT_TYPE_NOTIFY_SETREUID
	ES_EVENT_TYPE_NOTIFY_SETREGID
	ES_EVENT_TYPE_AUTH_COPYFILE
	ES_EVENT_TYPE_NOTIFY_COPYFILE
	// The following events are available beginning in macOS 13.0
	ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
	ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
	ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
	ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN
	ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT
	ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
	ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
	ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
	ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
	ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
	ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
	ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
	ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT
	ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
	ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
	// The following events are available beginning in macOS 14.0
	ES_EVENT_TYPE_NOTIFY_PROFILE_ADD
	ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE
	ES_EVENT_TYPE_NOTIFY_SU
	ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION
	ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT
	ES_EVENT_TYPE_NOTIFY_SUDO
	ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD
	ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE
	ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET
	ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD
	ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER
	ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER
	ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD
	ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE
	ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET
	ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER
	ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP
	ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER
	ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP
	ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
	// ES_EVENT_TYPE_LAST is not a valid event type but a convenience
	// value for operating on the range of defined event types.
	// This value may change between releases and was available
	// beginning in macOS 10.15
	ES_EVENT_TYPE_LAST
)

/*
 * Valid authorization values to be used when responding to a Es_message_t auth event
 */
type Es_auth_result_t int

const (
	/// The event is authorized and should be allowed to continue
	ES_AUTH_RESULT_ALLOW Es_auth_result_t = iota
	/// The event is not authorized and should be blocked
	ES_AUTH_RESULT_DENY
)

/*
 * Valid values for the result_type of Es_result_t to indicate the appropriate union member to use
 */
type Es_result_type_t int

const (
	/// The result is an auth result
	ES_RESULT_TYPE_AUTH = iota
	/// The result is a flags result
	ES_RESULT_TYPE_FLAGS
)

/*
 * Return value for functions that can only fail in one way
 */
type Es_return_t int

const (
	ES_RETURN_SUCCESS = iota
	ES_RETURN_ERROR
)

/*
 * Error conditions for responding to a message
 */
type Es_respond_result_t int

const (
	ES_RESPOND_RESULT_SUCCESS = iota
	///One or more invalid arguments were provided
	ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT
	///Communication with the ES subsystem failed
	ES_RESPOND_RESULT_ERR_INTERNAL
	///The message being responded to could not be found
	ES_RESPOND_RESULT_NOT_FOUND
	///The provided message has been responded to more than once
	ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE
	///Either an inappropriate response API was used for the event type (ensure using proper
	///es_respond_auth_result or Es_respond_flags_result function) or the event is notification only.
	ES_RESPOND_RESULT_ERR_EVENT_TYPE
)

/*
 * Error conditions for creating a new client
 */
type Es_new_client_result_t int

const (
	ES_NEW_CLIENT_RESULT_SUCCESS Es_new_client_result_t = iota
	/// One or more invalid arguments were provided.
	ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT
	/// Communication with the ES subsystem failed  or other error condition.
	ES_NEW_CLIENT_RESULT_ERR_INTERNAL
	/// The caller is not properly entitled to connect.
	ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED
	/// The caller lacks Transparency  Consent  and Control (TCC) approval from the user.
	ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED
	/// The caller is not running as root.
	ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED
	/// The caller has reached the maximum number of allowed simultaneously connected clients.
	ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS
)

/*
 * Error conditions for clearing the authorisation caches
 */
type Es_clear_cache_result_t int

const (
	ES_CLEAR_CACHE_RESULT_SUCCESS Es_clear_cache_result_t = iota
	///Communication with the ES subsystem failed
	ES_CLEAR_CACHE_RESULT_ERR_INTERNAL
	///Rate of calls is too high. Slow down.
	ES_CLEAR_CACHE_RESULT_ERR_THROTTLE
)

/*
 * Structure buffer with size
 */
type Es_token_t struct {
	// Size of the `data in bytes
	size int64
	data bytes.Buffer
}

/*
 * Structure for handling strings
 */
type Es_string_token_t struct {
	// Length of the `data. Equivalent to strlen().
	length int64
	data   string
}

/*
 * Values that will be paired with path strings to describe the type of the path
 */
type Es_mute_path_type_t int

const (
	/// Value to describe a path prefix
	ES_MUTE_PATH_TYPE_PREFIX Es_mute_path_type_t = iota
	/// Value to describe a path literal
	ES_MUTE_PATH_TYPE_LITERAL
	/// Value to describe a target path prefix
	ES_MUTE_PATH_TYPE_TARGET_PREFIX
	/// Value to describe a target path literal
	ES_MUTE_PATH_TYPE_TARGET_LITERAL
)

/*
 * Structure to describe attributes of a muted path.
 *
 * type_ Indicates if the path is a prefix or literal  and what type of muting applies.
 * event_count The number of events contained in the `events` array.
 * events Array of event types for which the path is muted.
 * path The muted path. (Note: Es_string_token_t is a char array and length)
 */
type Es_muted_path_t struct {
	type_       Es_mute_path_type_t
	event_count uint64
	events      []Es_event_type_t
	path        Es_string_token_t
}

/*
 * Structure for a set of muted paths.
 *
 * count The number of elements in the `paths` array.
 * paths Array of muted paths.
 */
type Es_muted_paths_t struct {
	count int64
	paths []Es_muted_path_t
}

/*
 * Structure to describe attributes of a muted process.
 *
 * token The audit token of a muted process.
 * event_count The number of events contained in the `events` array.
 * events Array of event types for which the process is muted.
 */
type Es_muted_process_t struct {
	audit_token audit_token_t
	event_count uint64
	events      []Es_event_type_t
}

/*
 * Structure for a set of muted processes.
 *
 * count The number of elements in the `processes` array.
 * processes Array of muted processes.
 */
type Es_muted_processes_t struct {
	count     uint64
	processes Es_muted_process_t
}

/*
 * Type of a network address.
 */
type Es_address_type_t int

const (
	/// No source address available.
	ES_ADDRESS_TYPE_NONE = iota
	/// Source address is IPv4.
	ES_ADDRESS_TYPE_IPV4
	/// Source address is IPv6.
	ES_ADDRESS_TYPE_IPV6
	/// Source address is named UNIX socket.
	ES_ADDRESS_TYPE_NAMED_SOCKET
)

type Es_mute_inversion_type_t int

const (
	ES_MUTE_INVERSION_TYPE_PROCESS = iota
	ES_MUTE_INVERSION_TYPE_PATH
	ES_MUTE_INVERSION_TYPE_TARGET_PATH
	ES_MUTE_INVERSION_TYPE_LAST
)

type Es_mute_inverted_return_t int

const (
	/// The type of muted queried was inverted
	ES_MUTE_INVERTED = iota
	/// The type of muted queried was not inverted
	ES_MUTE_NOT_INVERTED
	/// There was an error querying mute inversion state
	ES_MUTE_INVERTED_ERROR
)

/*
 * The class of rules used to evaluate the petition for a specific authorization right
 */
type Es_authorization_rule_class_t int

const (
	/// Right is judged on user properties
	ES_AUTHORIZATION_RULE_CLASS_USER = iota
	/// Right is judged by a tree of sub-rules
	ES_AUTHORIZATION_RULE_CLASS_RULE
	/// Right is judged by one or more plugins
	ES_AUTHORIZATION_RULE_CLASS_MECHANISM
	/// Right is always granted
	ES_AUTHORIZATION_RULE_CLASS_ALLOW
	/// Right is always denied
	ES_AUTHORIZATION_RULE_CLASS_DENY
	/// Right is unknown
	ES_AUTHORIZATION_RULE_CLASS_UNKNOWN
	/// Right is invalid
	ES_AUTHORIZATION_RULE_CLASS_INVALID
)

// The following types are used in OpenDirectory (od) events
/*
 * Type of a group member
 */
type Es_od_member_type_t int

const (
	/// Group member is a user  designated by name
	ES_OD_MEMBER_TYPE_USER_NAME = iota
	/// Group member is a user  designated by UUID
	ES_OD_MEMBER_TYPE_USER_UUID
	/// Group member is another group  designated by UUID
	ES_OD_MEMBER_TYPE_GROUP_UUID
)

/*
 * Type of an account
 */
type Es_od_account_type_t int

const (
	ES_OD_ACCOUNT_TYPE_USER = iota
	ES_OD_ACCOUNT_TYPE_COMPUTER
)

/*
 * Type of a record
 */
type Es_od_record_type_t int

const (
	ES_OD_RECORD_TYPE_USER = iota
	ES_OD_RECORD_TYPE_GROUP
)
