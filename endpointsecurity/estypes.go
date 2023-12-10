package endpointsecurity

import "bytes"

type audit_token_t struct {
	val [8]uint32
}

type es_action_type_t int

const (
	ES_ACTION_TYPE_AUTH es_action_type_t = iota
	ES_ACTION_TYPE_NOTIFY
)

type es_set_or_clear_t int

const (
	ES_SET es_set_or_clear_t = iota
	ES_CLEAR
)

/**
 * @brief This enum describes the type of the es_event_proc_check_t event that are currently used
 *
 * @note ES_PROC_CHECK_TYPE_KERNMSGBUF  ES_PROC_CHECK_TYPE_TERMINATE and
 * ES_PROC_CHECK_TYPE_UDATA_INFO are deprecated and no proc_check messages will be generated
 * for the corresponding proc_info call numbers.
 * The terminate callnum is covered by the signal event.
 */
type es_proc_check_type_t int

const (
	ES_PROC_CHECK_TYPE_LISTPIDS        es_proc_check_type_t = 0x1
	ES_PROC_CHECK_TYPE_PIDINFO         es_proc_check_type_t = 0x2
	ES_PROC_CHECK_TYPE_PIDFDINFO       es_proc_check_type_t = 0x3
	ES_PROC_CHECK_TYPE_KERNMSGBUF      es_proc_check_type_t = 0x4 // deprecated  not generated
	ES_PROC_CHECK_TYPE_SETCONTROL      es_proc_check_type_t = 0x5
	ES_PROC_CHECK_TYPE_PIDFILEPORTINFO es_proc_check_type_t = 0x6
	ES_PROC_CHECK_TYPE_TERMINATE       es_proc_check_type_t = 0x7 // deprecated  not generated
	ES_PROC_CHECK_TYPE_DIRTYCONTROL    es_proc_check_type_t = 0x8
	ES_PROC_CHECK_TYPE_PIDRUSAGE       es_proc_check_type_t = 0x9
	ES_PROC_CHECK_TYPE_UDATA_INFOv     es_proc_check_type_t = 0xe // deprecated  not generated
)

/**
 * @brief This enum describes the types of XPC service domains.
 */
type es_xpc_domain_type_t int

const (
	ES_XPC_DOMAIN_TYPE_SYSTEM es_xpc_domain_type_t = iota + 1
	ES_XPC_DOMAIN_TYPE_USER
	ES_XPC_DOMAIN_TYPE_USER_LOGIN
	ES_XPC_DOMAIN_TYPE_SESSION
	ES_XPC_DOMAIN_TYPE_PID
	ES_XPC_DOMAIN_TYPE_MANAGER
	ES_XPC_DOMAIN_TYPE_PORT
	ES_XPC_DOMAIN_TYPE_GUI
)

/**
 * @brief This enum describes the types of authentications that
 * ES_EVENT_TYPE_NOTIFY_AUTHENTICATION can describe.
 */
type es_authentication_type_t int

const (
	ES_AUTHENTICATION_TYPE_OD es_authentication_type_t = iota
	ES_AUTHENTICATION_TYPE_TOUCHID
	ES_AUTHENTICATION_TYPE_TOKEN
	ES_AUTHENTICATION_TYPE_AUTO_UNLOCK
	// ES_AUTHENTICATION_TYPE_LAST is not a valid type of authentication
	// but is a convenience value to operate on the range of defined
	// authentication types.
	ES_AUTHENTICATION_TYPE_LAST
)

/**
 * The valid event types recognized by EndpointSecurity
 *
 * @discussion When a program subscribes to and receives an AUTH-related event  it must respond
 * with an appropriate result indicating whether or not the operation should be allowed to continue.
 * The valid API options are:
 * - es_respond_auth_result
 * - es_respond_flags_result
 *
 * Currently  only ES_EVENT_TYPE_AUTH_OPEN must use es_respond_flags_result. All other AUTH events
 * must use es_respond_auth_result.
 */
type es_event_type_t int

const (
	// The following events are available beginning in macOS 10.15
	ES_EVENT_TYPE_AUTH_EXEC es_event_type_t = iota
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

/**
 * @brief Valid authorization values to be used when responding to a es_message_t auth event
 */
type es_auth_result_t int

const (
	/// The event is authorized and should be allowed to continue
	ES_AUTH_RESULT_ALLOW es_auth_result_t = iota
	/// The event is not authorized and should be blocked
	ES_AUTH_RESULT_DENY
)

/**
 * @brief Valid values for the result_type of es_result_t to indicate the appropriate union member to use
 */
type es_result_type_t int

const (
	/// The result is an auth result
	ES_RESULT_TYPE_AUTH = iota
	/// The result is a flags result
	ES_RESULT_TYPE_FLAGS
)

/**
 * @brief Return value for functions that can only fail in one way
 */
type es_return_t int

const (
	ES_RETURN_SUCCESS = iota
	ES_RETURN_ERROR
)

/**
 * @brief Error conditions for responding to a message
 */
type es_respond_result_t int

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
	///es_respond_auth_result or es_respond_flags_result function) or the event is notification only.
	ES_RESPOND_RESULT_ERR_EVENT_TYPE
)

/**
 * @brief Error conditions for creating a new client
 */
type es_new_client_result_t int

const (
	ES_NEW_CLIENT_RESULT_SUCCESS es_new_client_result_t = iota
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

/**
 * @brief Error conditions for clearing the authorisation caches
 */
type es_clear_cache_result_t int

const (
	ES_CLEAR_CACHE_RESULT_SUCCESS es_clear_cache_result_t = iota
	///Communication with the ES subsystem failed
	ES_CLEAR_CACHE_RESULT_ERR_INTERNAL
	///Rate of calls is too high. Slow down.
	ES_CLEAR_CACHE_RESULT_ERR_THROTTLE
)

/**
 * @brief Structure buffer with size
 */
type es_token_t struct {
	// Size of the `data` field in bytes
	size int64
	data bytes.Buffer
}

/**
 * @brief Structure for handling strings
 */
type es_string_token_t struct {
	// Length of the `data` field. Equivalent to strlen().
	length int64
	data   string
}

/**
 * @brief Values that will be paired with path strings to describe the type of the path
 */
type es_mute_path_type_t int

const (
	/// Value to describe a path prefix
	ES_MUTE_PATH_TYPE_PREFIX es_mute_path_type_t = iota
	/// Value to describe a path literal
	ES_MUTE_PATH_TYPE_LITERAL
	/// Value to describe a target path prefix
	ES_MUTE_PATH_TYPE_TARGET_PREFIX
	/// Value to describe a target path literal
	ES_MUTE_PATH_TYPE_TARGET_LITERAL
)

/**
 * Structure to describe attributes of a muted path.
 *
 * @field type Indicates if the path is a prefix or literal  and what type of muting applies.
 * @field event_count The number of events contained in the `events` array.
 * @field events Array of event types for which the path is muted.
 * @field path The muted path. (Note: es_string_token_t is a char array and length)
 */
type es_muted_path_t struct {
	type_       es_mute_path_type_t
	event_count uint64
	events      []es_event_type_t
	path        es_string_token_t
}

/**
 * Structure for a set of muted paths.
 *
 * @field count The number of elements in the `paths` array.
 * @field paths Array of muted paths.
 */
type es_muted_paths_t struct {
	count int64
	paths []es_muted_path_t
}

/**
 * Structure to describe attributes of a muted process.
 *
 * @field token The audit token of a muted process.
 * @field event_count The number of events contained in the `events` array.
 * @field events Array of event types for which the process is muted.
 */
type es_muted_process_t struct {
	audit_token audit_token_t
	event_count uint64
	events      []es_event_type_t
}

/**
 * Structure for a set of muted processes.
 *
 * @field count The number of elements in the `processes` array.
 * @field processes Array of muted processes.
 */
type es_muted_processes_t struct {
	count     uint64
	processes es_muted_process_t
}

/**
 * Type of a network address.
 */
type es_address_type_t int

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

type es_mute_inversion_type_t int

const (
	ES_MUTE_INVERSION_TYPE_PROCESS = iota
	ES_MUTE_INVERSION_TYPE_PATH
	ES_MUTE_INVERSION_TYPE_TARGET_PATH
	ES_MUTE_INVERSION_TYPE_LAST
)

type es_mute_inverted_return_t int

const (
	/// The type of muted queried was inverted
	ES_MUTE_INVERTED = iota
	/// The type of muted queried was not inverted
	ES_MUTE_NOT_INVERTED
	/// There was an error querying mute inversion state
	ES_MUTE_INVERTED_ERROR
)

/**
 * The class of rules used to evaluate the petition for a specific authorization right
 */
type es_authorization_rule_class_t int

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
/**
 * Type of a group member
 */
type es_od_member_type_t int

const (
	/// Group member is a user  designated by name
	ES_OD_MEMBER_TYPE_USER_NAME = iota
	/// Group member is a user  designated by UUID
	ES_OD_MEMBER_TYPE_USER_UUID
	/// Group member is another group  designated by UUID
	ES_OD_MEMBER_TYPE_GROUP_UUID
)

/**
 * Type of an account
 */
type es_od_account_type_t int

const (
	ES_OD_ACCOUNT_TYPE_USER = iota
	ES_OD_ACCOUNT_TYPE_COMPUTER
)

/**
 * Type of a record
 */
type es_od_record_type_t int

const (
	ES_OD_RECORD_TYPE_USER = iota
	ES_OD_RECORD_TYPE_GROUP
)
