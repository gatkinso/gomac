package endpointsecurity

import (
	"os"
	"time"
	"unsafe"
)

type acl_t struct {
	//TODO
}

type statfs_t struct {
	//TODO
}

type uuid_t struct {
	//TODO
}

/**
 * The EndpointSecurity subsystem is responsible for creating, populating and
 * delivering these data structures to ES clients.
 */

/**
 * A note on userspace events:
 *
 * Before macOS 13.0 almost all ES events were created by `xnu` (the macOS kernel).
 * Such events are *mandatory*.
 * If no `es_event_setuid_t` event is emitted then no `setuid` took place. This is a secuirty guarantee.
 * Most events added in macOS 13 and 14 are emitted by userspace binaries and frameworks.
 * ES still guarantees that if an event was not emitted *by that binary or framework* then it did not happen, but this is not quite the same guarantee.
 *
 * Consider `es_event_su_t`.
 * This event is created by the `su` binary first shipped in macOS 14.0, but it's entirely possible for a user to install (or compile) a different `su`!
 * ES only guarantees that the platform binary shipped with macOS emits `es_event_su_t` events.
 * As such `es_event_su_t` does not provide the same security guarantee that `es_event_setuid_t` does.
 *
 * When a user invokes the platform `su` binary ES will emit both `es_event_su_t` and `es_event_setuid_t` events.
 * When a user compiles their own `su` binary from source and executes it:
 *   ES will emit an `es_event_setuid_t` event.
 *   ES will NOT emit an `es_event_su_t`.
 *
 * Userspace events are inherntly discretionary.
 * It is the at the users discrtion as to wether the use the builtin binaries/frameworks or not.
 * Kernel events are mandatory. There is no `setuid` syscall that ES does not interdict.
 *
 * The following events are created by userspace binaries or frameworks:
 *   ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE
 *   ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE
 *   ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE
 *   ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE
 *   ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
 *   ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
 *   ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
 *   ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN
 *   ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT
 *   ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
 *   ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
 *   ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
 *   ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
 *   ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
 *   ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
 *   ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
 *   ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT
 *   ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
 *   ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
 *   ES_EVENT_TYPE_NOTIFY_PROFILE_ADD
 *   ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE
 *   ES_EVENT_TYPE_NOTIFY_SU
 *   ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION
 *   ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT
 *   ES_EVENT_TYPE_NOTIFY_SUDO
 *   ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD
 *   ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE
 *   ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET
 *   ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD
 *   ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER
 *   ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER
 *   ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD
 *   ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE
 *   ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET
 *   ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER
 *   ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP
 *   ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER
 *   ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP
 */

/**
 * @brief Es_file_t provides the stat information and path to a file that relates to a security
 * event. The path may be truncated, which is indicated by the path_truncated flag.
 *
 * @field path Absolute path of the file
 * @field path_truncated Indicates if the path field was truncated
 * @field stat stat of file. See `man 2 stat` for details
 *
 * @note For the FAT family of filesystems the `stat.st_ino` field is set to 999999999 for empty files
 *
 * @discussion For files with a link count greater than 1, the absolute path given may not be the only absolute path that exists, and which hard link the emitted path points to is undefined.
 *
 * Overlong paths are truncated at a maximum length that currently is 16K, though that number is not considered API and may change at any time.
 *
 */
type Es_file_t struct {
	path           string
	path_truncated bool
	stat           os.FileInfo
}

/**
 * @brief Information related to a thread.
 *
 * @field thread_id The unique thread ID of the thread.
 */
type Es_thread_t struct {
	thread_id uint64
}

/**
 * @brief Information related to a process. This is used both for describing processes that
 * performed an action (e.g. in the case of the `es_message_t` `process` field, or are targets
 * of an action (e.g. for exec events this describes the new process being executed, for signal
 * events this describes the process that will receive the signal).
 *
 * @field audit_token Audit token of the process.
 * @field ppid Parent pid of the process. It is recommended to instead use the parent_audit_token field.
 *        @see parent_audit_token
 * @field original_ppid Original ppid of the process.  This field stays constant even in the event
 *        this process is reparented.
 * @field group_id Process group id the process belongs to.
 * @field session_id Session id the process belongs to.
 * @field codesigning_flags Code signing flags of the process.  The values for these flags can be
 *        found in the include file `cs_blobs.h` (`#include <kern/cs_blobs.h>`).
 * @field is_es_client Indicates this process has the Endpoint Security entitlement.
 * @field cdhash The code directory hash of the code signature associated with this process.
 * @field signing_id The signing id of the code signature associated with this process.
 * @field team_id The team id of the code signature associated with this process.
 * @field executable The executable file that is executing in this process.
 * @field tty The TTY this process is associated with, or NULL if the process does not have an
 *        associated TTY.  The TTY is a property of the POSIX session the process belongs to.
 *        A process' session may be associated with a TTY independently from whether its stdin
 *        or any other file descriptors point to a TTY device (as per isatty(3), tty(1)).
 *        Field available only if message version >= 2.
 * @field start_time Process start time, i.e. time of fork creating this process.
 *        Field available only if message version >= 3.
 * @field responsible_audit_token audit token of the process responsible for this process, which
 *        may be the process itself in case there is no responsible process or the responsible
 *        process has already exited.
 *        Field available only if message version >= 4.
 * @field parent_audit_token The audit token of the parent process
 *        Field available only if message version >= 4.
 *
 * @discussion
 * - Values such as pid, pidversion, uid, gid, etc. can be extracted from audit tokens using API
 *   provided in libbsm.
 * - The tuple (pid, pidversion) identifies a specific process execution, and should be used to link
 *   events to the process that emitted them.  Executing an executable image in a process using the
 *   exec or posix_spawn family of syscalls increments the pidversion.  However, (pid, pidversion)
 *   is not meant to be unique across reboots or across multiple systems.
 * - Clients should take caution when processing events where `is_es_client` is true. If multiple ES
 *   clients exist, actions taken by one client could trigger additional actions by the other client,
 *   causing a potentially infinite cycle.
 * - Fields related to code signing in the target `Es_process_t` reflect the state of the process
 *   at the time the message is generated.  In the specific case of exec, this is after the exec
 *   completed in the kernel, but before any code in the process has started executing.  At that
 *   point, XNU has validated the signature itself and has verified that the CDHash is correct in
 *   that the hash of all the individual page hashes in the Code Directory matches the signed CDHash,
 *   essentially verifying the signature was not tampered with.  However, individual page hashes are
 *   not verified by XNU until the corresponding pages are paged in once they are accessed while the
 *   binary executes.  It is not until the individual pages are paged in that XNU determines if a
 *   binary has been tampered with and will update the code signing flags accordingly.
 *   EndpointSecurity provides clients the current state of the CS flags in the `codesigning_flags`
 *   member of the `Es_process_t` struct.  The CS_VALID bit in the `codesigning_flags` means that
 *   everything the kernel has validated up to that point in time was valid, but not that there has
 *   been a full validation of all the pages in the executable file.  If page content has been
 *   tampered with in the executable, we won't know until that page is paged in.  At that time, the
 *   process will have its CS_VALID bit cleared and, if CS_KILL is set, the process will be killed,
 *   preventing any tampered code from being executed.  CS_KILL is generally set for platform
 *   binaries and for binaries having opted into the hardened runtime.  An ES client wishing to
 *   detect tampered code before it is paged in, for example at exec time, can use the Security
 *   framework to do so, but should be cautious of the potentially significant performance cost.  The
 *   EndpointSecurity subsystem itself has no role in verifying the validity of code signatures.
 */
type Es_process_t struct {
	audit_token             audit_token_t
	ppid                    int32
	original_ppid           int32
	group_id                int32
	session_id              int32
	codesigning_flags       uint32
	is_platform_binary      bool
	is_es_client            bool
	cdhash                  [20]uint8
	signing_id              Es_string_token_t
	team_id                 Es_string_token_t
	executable              *Es_file_t
	tty                     *Es_file_t
	start_time              time.Time
	responsible_audit_token audit_token_t
	parent_audit_token      audit_token_t
}

/**
 * @brief Describes machine-specific thread state as used by `thread_create_running` and other
 * Mach API functions.
 *
 * @field flavor Indicates the representation of the machine-specific thread state.
 * @field state The machine-specific thread state, equivalent to thread_state_t in Mach APIs.
 *
 * @note The size subfield of the state field is in bytes, NOT natural_t units.  Definitions
 * for working with thread state can be found in the include file `mach/thread_status.h` and
 * corresponding machine-dependent headers.
 */
type Es_thread_state_t struct {
	flavor int
	state  Es_token_t
}

/**
 * @brief Structure for describing an open file descriptor
 *
 * @field fd File descriptor number
 * @field fdtype File descriptor type, as libproc fdtype
 *
 * Fields available only if fdtype == PROX_FDTYPE_PIPE:
 * @field extra.pipe.pipe_id Unique id of the pipe for correlation with other
 *        file descriptors pointing to the same or other end of the same pipe.
 */
type Es_fd_t struct {
	fd     int32
	fdtype uint32
	pipe   struct {
		pipe_id uint64
	}
}

type Es_btm_item_type_t int

const (
	ES_BTM_ITEM_TYPE_USER_ITEM Es_btm_item_type_t = iota
	ES_BTM_ITEM_TYPE_APP
	ES_BTM_ITEM_TYPE_LOGIN_ITEM
	ES_BTM_ITEM_TYPE_AGENT
	ES_BTM_ITEM_TYPE_DAEMON
)

/**
 * @brief Structure describing a BTM launch item
 *
 * @field item_type             Type of launch item.
 * @field legacy                True iff item is a legacy plist.
 * @field managed               True iff item is managed by MDM.
 * @field uid                   User ID for the item (may be user nobody (-2)).
 * @field item_url              URL for item.
 *                              If file URL describing a relative path, it is relative
 *                              to app_url.
 * @field app_url               Optional.  URL for app the item is attributed to.
 */
type Es_btm_launch_item_t struct {
	item_type Es_btm_item_type_t
	legacy    bool
	managed   bool
	uid       int
	item_url  Es_string_token_t
	app_url   Es_string_token_t
}

type Es_profile_source_t int

const (
	ES_PROFILE_SOURCE_MANAGED Es_profile_source_t = iota
	ES_PROFILE_SOURCE_INSTALL
)

/**
 * @brief Structure describing a Profile event
 *
 * @field identifier		Profile identifier.
 * @field uuid         		Profile UUID.
 * @field install_source	Source of Profile installation (MDM/Manual Install)
 * @field organization		Profile organization name.
 * @field display_name		Profile display name.
 * @field scope				Profile scope.
 */
type Es_profile_t struct {
	identifier     Es_string_token_t
	uuid           Es_string_token_t
	install_source Es_profile_source_t
	organization   Es_string_token_t
	display_name   Es_string_token_t
	scope          Es_string_token_t
}

type cpu_type_t struct {
	// define cpu_type_t struct fields here
}

type cpu_subtype_t struct {
	// define cpu_subtype_t struct fields here
}

/**
 * @brief Execute a new process
 *
 * @field target The new process that is being executed
 * @field dyld_exec_path The exec path passed up to dyld, before symlink resolution.
 *        This is the path argument to execve(2) or posix_spawn(2), or the interpreter
 *        from the shebang line for scripts run through the shell script image activator.
 *        Field available only if message version >= 7.
 * @field script Script being executed by interpreter. This field is only valid if a script was
 *        executed directly and not as an argument to the interpreter (e.g. `./foo.sh` not `/bin/sh ./foo.sh`)
 *        Field available only if message version >= 2.
 * @field cwd Current working directory at exec time.
 *        Field available only if message version >= 3.
 * @field last_fd Highest open file descriptor after the exec completed.
 *        This number is equal to or larger than the highest number of file descriptors available
 *        via `es_exec_fd_count` and `es_exec_fd`, in which case EndpointSecurity has capped the
 *        number of file descriptors available in the message.  File descriptors for open files are
 *        not necessarily contiguous.  The exact number of open file descriptors is not available.
 *        Field available only if message version >= 4.
 * @field image_cputype The CPU type of the executable image which is being executed.
 *        In case of translation, this may be a different architecture than the one of the system.
 *        Field available only if message version >= 6.
 * @field image_cpusubtype The CPU subtype of the executable image.
 *        Field available only if message version >= 6.
 *
 * @note Process arguments, environment variables and file descriptors are packed, use API functions
 * to access them: `es_exec_arg`, `es_exec_arg_count`, `es_exec_env`, `es_exec_env_count`,
 * `es_exec_fd` and `es_exec_fd_count`.
 *
 * @note The API may only return descriptions for a subset of open file descriptors; how many and
 * which file descriptors are available as part of exec events is not considered API and can change
 * in future releases.
 *
 * @note The CPU type and subtype correspond to CPU_TYPE_* and CPU_SUBTYPE_* macros defined in
 * `<mach/machine.h>`.
 *
 * @note Fields related to code signing in `target` represent kernel state for the process at the
 * point in time the exec has completed, but the binary has not started running yet.  Because code
 * pages are not validated until they are paged in, this means that modifications to code pages
 * would not have been detected yet at this point.  For a more thorough explanation, please see the
 * documentation for `Es_process_t`.
 *
 * @note There are two `Es_process_t` fields that are represented in an `es_message_t` that contains
 * an `es_event_exec_t`. The `Es_process_t` within the `es_message_t` struct (named "process")
 * contains information about the program that calls execve(2) (or posix_spawn(2)). This information
 * is gathered prior to the program being replaced. The other `Es_process_t`, within the
 * `es_event_exec_t` struct (named "target"), contains information about the program after the image
 * has been replaced by execve(2) (or posix_spawn(2)). This means that both `Es_process_t` structs
 * refer to the same process (as identified by pid), but not necessarily the same program, and
 * definitely not the same program execution (as identified by pid, pidversion tuple). The
 * `audit_token_t` structs contained in the two different `Es_process_t` structs will not be
 * identical: the pidversion field will be updated, and the uid/gid values may be different if the
 * new program had setuid/setgid permission bits set.
 *
 * @note Cache key for this event type:  (process executable file, target executable file)
 */
type Es_event_exec_t struct {
	target           *Es_process_t
	dyld_exec_path   Es_string_token_t
	reserved         [64]uint8
	script           *Es_file_t
	cwd              *Es_file_t
	last_fd          int
	image_cputype    cpu_type_t
	image_cpusubtype cpu_subtype_t
}

/**
 * @brief Open a file system object
 *
 * @field fflag The desired flags to be used when opening `file` (see note)
 * @field file The file that will be opened
 *
 * @note: The `fflag` field represents the mask as applied by the kernel, not as represented by typical
 * open(2) `oflag` values. When responding to `ES_EVENT_TYPE_AUTH_OPEN` events using
 * Es_respond_flags_result(), ensure that the same FFLAG values are used (e.g. FREAD, FWRITE instead
 * of O_RDONLY, O_RDWR, etc...).
 *
 * @note Cache key for this event type:  (process executable file, file that will be opened)
 *
 * @see fcntl.h
 */
type Es_event_open_t struct {
	fflag    int32
	file     *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Load a kernel extension
 *
 * @field identifier The signing identifier of the kext being loaded
 *
 * @note This event type does not support caching.
 */
type Es_event_kextload_t struct {
	identifier Es_string_token_t
	reserved   [64]uint8
}

/**
 * @brief Unload a kernel extension
 *
 * @field identifier The signing identifier of the kext being unloaded
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_kextunload_t struct {
	identifier Es_string_token_t
	reserved   [64]uint8
}

/**
 * @brief Unlink a file system object
 *
 * @field target The object that will be removed
 * @field parent_dir The parent directory of the `target` file system object
 *
 * @note This event can fire multiple times for a single syscall, for example when the syscall
 *       has to be retried due to racing VFS operations.
 *
 * @note This event type does not support caching.
 */
type Es_event_unlink_t struct {
	target     *Es_file_t
	parent_dir *Es_file_t
	reserved   [64]uint8
}

/**
 * @brief Memory map a file
 *
 * @field protection The protection (region accessibility) value
 * @field max_protection The maximum allowed protection value the operating system will respect
 * @field flags The type and attributes of the mapped file
 * @field file_pos The offset into `source` that will be mapped
 * @field source The file system object being mapped
 *
 * @note Cache key for this event type:  (process executable file, source file)
 */
type Es_event_mmap_t struct {
	protection     int32
	max_protection int32
	flags          int32
	file_pos       uint64
	source         *Es_file_t
	reserved       [64]uint8
}

/**
 * @brief Link to a file
 *
 * @field source The existing object to which a hard link will be created
 * @field target_dir The directory in which the link will be created
 * @field target_filename The name of the new object linked to `source`
 *
 * @note This event type does not support caching.
 */
type Es_event_link_t struct {
	source          *Es_file_t
	target_dir      *Es_file_t
	target_filename Es_string_token_t
	reserved        [64]uint8
}

/**
* @brief Mount a file system
*
* @field statfs The file system stats for the file system being mounted
*
* @note Cache key for this event type:  (process executable file, mount point)
 */
type Es_event_mount_t struct {
	statfs   *statfs_t
	reserved [64]uint8
}

/**
 * @brief Unmount a file system
 *
 * @field statfs The file system stats for the file system being unmounted
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_unmount_t struct {
	statfs   *statfs_t
	reserved [64]uint8
}

/**
 * @brief Remount a file system
 *
 * @field statfs The file system stats for the file system being remounted
 *
 * @note This event type does not support caching.
 */
type Es_event_remount_t struct {
	statfs   *statfs_t
	reserved [64]uint8
}

/**
 * @brief Fork a new process
 *
 * @field child The child process that was created
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_fork_t struct {
	child    *Es_process_t
	reserved [64]uint8
}

/**
 * @brief Control protection of pages
 *
 * @field protection The desired new protection value
 * @field address The base address to which the protection value will apply
 * @field size The size of the memory region the protection value will apply
 *
 * @note This event type does not support caching.
 */
type Es_event_mprotect_t struct {
	protection int32
	address    uint64
	size       uint64
	reserved   [64]uint8
}

/**
 * @brief Send a signal to a process
 *
 * @field sig The signal number to be delivered
 * @field target The process that will receive the signal
 *
 * @note This event will not fire if a process sends a signal to itself.
 *
 * @note Cache key for this event type:  (process executable file, target process executable file)
 */
type Es_event_signal_t struct {
	sig      int
	target   *Es_process_t
	reserved [64]uint8
}

type Es_destination_type_t int

const (
	ES_DESTINATION_TYPE_EXISTING_FILE Es_destination_type_t = iota
	ES_DESTINATION_TYPE_NEW_PATH
)

/**
 * @brief Rename a file system object
 *
 * @field source The source file that is being renamed
 * @field destination_type Whether or not the destination refers to an existing or new file
 * @field destination Information about the destination of the renamed file (see note)
 * @field existing_file The destination file that will be overwritten
 * @field new_path Information regarding the destination of a newly created file
 * @field dir The directory into which the file will be renamed
 * @field filename The name of the new file that will be created
 *
 * @note The `destination_type` field describes which member in the `destination` union should
 * accessed. `ES_DESTINATION_TYPE_EXISTING_FILE` means that `existing_file` should be used,
 * `ES_DESTINATION_TYPE_NEW_PATH` means that the `new_path` struct should be used.
 *
 * @note This event can fire multiple times for a single syscall, for example when the syscall
 *       has to be retried due to racing VFS operations.
 *
 * @note This event type does not support caching.
 */
type Es_event_rename_t struct {
	source           *Es_file_t
	destination_type Es_destination_type_t
	destination      struct {
		existing_file *Es_file_t
		new_path      struct {
			dir      *Es_file_t
			filename Es_string_token_t
		}
	}
	reserved [64]uint8
}

/**
 * @brief Set an extended attribute
 *
 * @field target The file for which the extended attribute will be set
 * @field extattr The extended attribute which will be set
 *
 * @note This event type does not support caching.
 */
type Es_event_setextattr_t struct {
	target   *Es_file_t
	extattr  Es_string_token_t
	reserved [64]uint8
}

/**
 * @brief Retrieve an extended attribute
 *
 * @field target The file for which the extended attribute will be retrieved
 * @field extattr The extended attribute which will be retrieved
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_getextattr_t struct {
	target   *Es_file_t
	extattr  Es_string_token_t
	reserved [64]uint8
}

/**
 * @brief Delete an extended attribute
 *
 * @field target The file for which the extended attribute will be deleted
 * @field extattr The extended attribute which will be deleted
 *
 * @note This event type does not support caching.
 */
type Es_event_deleteextattr_t struct {
	target   *Es_file_t
	extattr  Es_string_token_t
	reserved [64]uint8
}

/**
 * @brief Modify file mode
 *
 * @field mode The desired new mode
 * @field target The file for which mode information will be modified
 *
 * @note The `mode` member is the desired new mode. The `target`
 * member's `stat` information contains the current mode.
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_setmode_t struct {
	mode     uint32
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Modify file flags information
 *
 * @field flags The desired new flags
 * @field target The file for which flags information will be modified
 *
 * @note The `flags` member is the desired set of new flags. The `target`
 * member's `stat` information contains the current set of flags.
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_setflags_t struct {
	flags    uint32
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Modify file owner information
 *
 * @field uid The desired new UID
 * @field gid The desired new GID
 * @field target The file for which owner information will be modified
 *
 * @note The `uid` and `gid` members are the desired new values. The `target`
 * member's `stat` information contains the current uid and gid values.
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_setowner_t struct {
	uid      uint32
	gid      uint32
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Close a file descriptor
 *
 * @field modified Set to TRUE if the target file being closed has been modified
 * @field target The file that is being closed
 * @field was_mapped_writable Indicates that at some point in the lifetime of the
 *        target file vnode it was mapped into a process as writable.
 *        Field available only if message version >= 6.
 *
 * @note This event type does not support caching (notify-only).
 *
 * `was_mapped_writable` only indicates whether the target file was mapped into writable memory or not for the lifetime of the vnode.
 * It does not indicate whether the file has actually been written to by way of writing to mapped memory, and it does not indicate whether the file is currently still mapped writable.
 * Correct interpretation requires consideration of vnode lifetimes in the kernel.
 *
 * The `modified` flag only reflects that a file was or was not modified by filesystem syscall.
 * If a file was only modifed though a memory mapping this flag will be false, but was_mapped_writable will be true.
 */
type Es_event_close_t struct {
	modified bool
	target   *Es_file_t
	reserved [64]uint8
}

type new_path_t struct {
	dir      Es_file_t
	filename string
	mode     os.FileMode
}

type destination_t struct {
	existing_file *Es_file_t
	np            new_path_t
}

/**
 * @brief Create a file system object
 *
 * @field destination_type Whether or not the destination refers to an existing file (see note)
 * @field destination Information about the destination of the new file (see note)
 * @field existing_file The file system object that was created
 * @field dir The directory in which the new file system object will be created
 * @field filename The name of the new file system object to create
 * @field acl The ACL that the new file system object got or gets created with.
 *        May be NULL if the file system object gets created without ACL.
 *        @note The acl provided cannot be directly used by functions within
 *        the <sys/acl.h> header. These functions can mutate the struct passed
 *        into them, which is not compatible with the immutable nature of
 *        Es_message_t. Additionally, because this field is minimally constructed,
 *        you must not use `acl_dup(3)` to get a mutable copy, as this can lead to
 *        out of bounds memory access. To obtain a acl_t struct that is able to be
 *        used with all functions within <sys/acl.h>, please use a combination of
 *        `acl_copy_ext(3)` followed by `acl_copy_int(3)`.
 *        Field available only if message version >= 2.
 *
 * @note If an object is being created but has not yet been created, the
 * `destination_type` will be `ES_DESTINATION_TYPE_NEW_PATH`.
 *
 * @note Typically `ES_EVENT_TYPE_NOTIFY_CREATE` events are fired after the
 * object has been created and the `destination_type` will be
 * `ES_DESTINATION_TYPE_EXISTING_FILE`. The exception to this is for
 * notifications that occur if an ES client responds to an
 * `ES_EVENT_TYPE_AUTH_CREATE` event with `ES_AUTH_RESULT_DENY`.
 *
 * @note This event can fire multiple times for a single syscall, for example when the syscall
 *       has to be retried due to racing VFS operations.
 *
 * @note This event type does not support caching.
 */
type Es_event_create_t struct {
	destination_type string
	destination      destination_t
	acl              *acl_t
}

/**
 * @brief Terminate a process
 *
 * @field stat The exit status of a process (same format as wait(2))
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_exit_t struct {
	stat     int
	reserved [64]uint8
}

/**
 * @brief Exchange data atomically between two files
 *
 * @field file1 The first file to be exchanged
 * @field file2 The second file to be exchanged
 *
 * @note This event type does not support caching.
 */
type Es_event_exchangedata_t struct {
	file1    *Es_file_t
	file2    *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Write to a file
 *
 * @field target The file being written to
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_write_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Truncate a file
 *
 * @field target The file that is being truncated
 *
 * @note This event type does not support caching.
 */
type Es_event_truncate_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Change directories
 *
 * @field target The desired new current working directory
 *
 * @note Cache key for this event type:  (process executable file, target directory)
 */
type Es_event_chdir_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief View stat information of a file
 *
 * @field target The file for which stat information will be retrieved
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_stat_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Change the root directory for a process
 *
 * @field target The directory which will be the new root
 *
 * @note Cache key for this event type:  (process executable file, target directory)
 */
type Es_event_chroot_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief List extended attributes of a file
 *
 * @field target The file for which extended attributes are being retrieved
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_listextattr_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Open a connection to an I/O Kit IOService
 *
 * @field user_client_type A constant specifying the type of connection to be
 *        created, interpreted only by the IOService's family.
 *        This field corresponds to the type argument to IOServiceOpen().
 * @field user_client_class Meta class name of the user client instance.
 *
 * This event is fired when a process calls IOServiceOpen() in order to open
 * a communications channel with an I/O Kit driver.  The event does not
 * correspond to driver <-> device communication and is neither providing
 * visibility nor access control into devices being attached.
 *
 * @note This event type does not support caching.
 */
type Es_event_iokit_open_t struct {
	user_client_type  uint32
	user_client_class Es_string_token_t
	reserved          [64]uint8
}

type Es_get_task_type_t int

const (
	ES_GET_TASK_TYPE_TASK_FOR_PID Es_get_task_type_t = iota
	ES_GET_TASK_TYPE_EXPOSE_TASK
	ES_GET_TASK_TYPE_IDENTITY_TOKEN
)

/**
 * @brief Get a process's task control port
 *
 * @field target The process for which the task control port will be retrieved.
 * @field type Type indicating how the process is obtaining the task port for
 *        the target process.
 *        Field available only if message version >= 5.
 *
 * This event is fired when a process obtains a send right to a task control
 * port (e.g. task_for_pid(), task_identity_token_get_task_port(),
 * processor_set_tasks() and other means).
 *
 * @note Task control ports were formerly known as simply "task ports".
 *
 * @note There are many legitimate reasons why a process might need to obtain
 * a send right to a task control port of another process, not limited to intending
 * to debug or suspend the target process.  For instance, frameworks and their
 * daemons may need to obtain a task control port to fulfill requests made by the
 * target process.  Obtaining a task control port is in itself not indicative of
 * malicious activity.  Denying system processes acquiring task control ports may
 * result in breaking system functionality in potentially fatal ways.
 *
 * @note Cache key for this event type:
 * (process executable file, target executable file)
 */
type Es_event_get_task_t struct {
	target   *Es_process_t
	type_    Es_get_task_type_t
	reserved [60]uint8
}

/**
 * @brief Get a process's task read port
 *
 * @field target The process for which the task read port will be retrieved.
 * @field type Type indicating how the process is obtaining the task port for
 *        the target process.
 *        Field available only if message version >= 5.
 *
 * This event is fired when a process obtains a send right to a task read
 * port (e.g. task_read_for_pid(), task_identity_token_get_task_port()).
 *
 * @note Cache key for this event type:
 * (process executable file, target executable file)
 */
type Es_event_get_task_read_t struct {
	target   *Es_process_t
	type_    Es_get_task_type_t
	reserved [60]uint8
}

/**
 * @brief Get a process's task inspect port
 *
 * @field target The process for which the task inspect port will be retrieved.
 * @field type Type indicating how the process is obtaining the task port for
 *        the target process.
 *        Field available only if message version >= 5.
 *
 * This event is fired when a process obtains a send right to a task inspect
 * port (e.g. task_inspect_for_pid(), task_identity_token_get_task_port()).
 *
 * @note This event type does not support caching.
 */
type Es_event_get_task_inspect_t struct {
	target   *Es_process_t
	type_    Es_get_task_type_t
	reserved [60]uint8
}

/**
 * @brief Get a process's task name port
 *
 * @field target The process for which the task name port will be retrieved.
 * @field type Type indicating how the process is obtaining the task port for
 *        the target process.
 *        Field available only if message version >= 5.
 *
 * This event is fired when a process obtains a send right to a task name
 * port (e.g. task_name_for_pid(), task_identity_token_get_task_port()).
 *
 * @note This event type does not support caching.
 */
type Es_event_get_task_name_t struct {
	target   *Es_process_t
	type_    Es_get_task_type_t
	reserved [60]uint8
}

/**
 * @brief Retrieve file system attributes
 *
 * @field attrlist The attributes that will be retrieved
 * @field target The file for which attributes will be retrieved
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_getattrlist_t struct {
	attrlist struct{}
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Set file system attributes
 *
 * @field attrlist The attributes that will be modified
 * @field target The file for which attributes will be modified
 *
 * @note This event type does not support caching.
 */
type Es_event_setattrlist_t struct {
	attrlist struct{}
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Update file contents via the FileProvider framework
 *
 * @field source The staged file that has had its contents updated
 * @field target_path The destination that the staged `source` file will be moved to
 *
 * @note This event type does not support caching.
 */
type Es_event_file_provider_update_t struct {
	source      *Es_file_t
	target_path Es_string_token_t
	reserved    [64]uint8
}

/**
 * @brief Materialize a file via the FileProvider framework
 *
 * @field source The staged file that has been materialized
 * @field target The destination of the staged `source` file
 *
 * @note This event type does not support caching.
 */
type Es_event_file_provider_materialize_t struct {
	instigator *Es_process_t
	source     *Es_file_t
	target     *Es_file_t
	reserved   [64]uint8
}

/**
 * @brief Resolve a symbolic link
 *
 * @field source The symbolic link that is attempting to be resolved
 *
 * @note This is not limited only to readlink(2). Other operations such as path lookups
 * can also cause this event to be fired.
 */
type Es_event_readlink_t struct {
	source   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Lookup a file system object
 *
 * @field source_dir The current directory
 * @field relative_target The path to lookup relative to the `source_dir`
 *
 * @note The `relative_target` data may contain untrusted user input.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_lookup_t struct {
	source_dir      *Es_file_t
	relative_target Es_string_token_t
	reserved        [64]uint8
}

/**
 * @brief Test file access
 *
 * @field mode Access permission to check
 * @field target The file to check for access
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_access_t struct {
	mode     int32
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Change file access and modification times (e.g. via utimes(2))
 *
 * @field target The path which will have its times modified
 * @field atime The desired new access time
 * @field mtime The desired new modification time
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_utimes_t struct {
	target   *Es_file_t
	atime    struct{}
	mtime    struct{}
	reserved [64]uint8
}

/**
 * @brief Clone a file
 *
 * @field source The file that will be cloned
 * @field target_dir The directory into which the `source` file will be cloned
 * @field target_name The name of the new file to which `source` will be cloned
 *
 * @note This event type does not support caching.
 */
type Es_event_clone_t struct {
	source      *Es_file_t
	target_file *Es_file_t
	target_dir  *Es_file_t
	target_name Es_string_token_t
	mode        uint32
	flags       int32
	reserved    [56]uint8
}

/**
 * @brief Copy a file using the copyfile syscall
 *
 * @field source The file that will be cloned
 * @field target_file The file existing at the target path that will be overwritten
 *                    by the copyfile operation.  NULL if no such file exists.
 * @field target_dir The directory into which the `source` file will be copied
 * @field target_name The name of the new file to which `source` will be copied
 * @field mode Corresponds to mode argument of the copyfile syscall
 * @field flags Corresponds to flags argument of the copyfile syscall
 *
 * @note Not to be confused with copyfile(3).
 * @note Prior to macOS 12.0, the copyfile syscall fired open, unlink and auth
 *       create events, but no notify create, nor write or close events.
 *
 * @note This event type does not support caching.
 */
type Es_event_copyfile_t struct {
	source      *Es_file_t
	target_file *Es_file_t
	target_dir  *Es_file_t
	target_name Es_string_token_t
	mode        uint32
	flags       int32
	reserved    [56]uint8
}

/**
 * @brief File control
 *
 * @field target The target file on which the file control command will be performed
 * @field cmd The `cmd` argument given to fcntl(2)
 *
 * @note This event type does not support caching.
 */
type Es_event_fcntl_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Read directory entries
 *
 * @field target The directory whose contents will be read
 *
 * @note Cache key for this event type:  (process executable file, target directory)
 */
type Es_event_readdir_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Retrieve file system path based on FSID
 *
 * @field target Describes the file system path that will be retrieved
 *
 * @note This event can fire multiple times for a single syscall, for example when the syscall
 *       has to be retried due to racing VFS operations.
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_fsgetpath_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Modify the system time
 *
 * @note This event is not fired if the program contains the entitlement
 * com.apple.private.settime. Additionally, even if an ES client responds to
 * ES_EVENT_TYPE_AUTH_SETTIME events with ES_AUTH_RESULT_ALLOW, the operation
 * may still fail for other reasons (e.g. unprivileged user).
 *
 * @note This event type does not support caching.
 */
type Es_event_settime_t struct {
	reserved [64]uint8
}

/**
 * @brief Duplicate a file descriptor
 *
 * @field target Describes the file the duplicated file descriptor points to
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_dup_t struct {
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief Fired when a UNIX-domain socket is about to be bound to a path.
 *
 * @field dir Describes the directory the socket file is created in.
 * @field filename The filename of the socket file.
 * @field mode The mode of the socket file.
 *
 * @note This event type does not support caching.
 */
type Es_event_uipc_bind_t struct {
	dir      *Es_file_t
	filename Es_string_token_t
	mode     uint32
	reserved [64]uint8
}

/**
 * @brief Fired when a UNIX-domain socket is about to be connected.
 *
 * @field file Describes the socket file that the socket is bound to.
 * @field domain The communications domain of the socket (see socket(2)).
 * @field type The type of the socket (see socket(2)).
 * @field protocol The protocol of the socket (see socket(2)).
 *
 * @note Cache key for this event type:  (process executable file, socket file)
 */
type Es_event_uipc_connect_t struct {
	target   *Es_file_t
	domain   int
	type_    int
	protocol int
	reserved [64]uint8
}

/**
 * @brief Set a file ACL.
 *
 * @field set_or_clear Describes whether or not the ACL on the `target` is being set or cleared
 * @field acl Union that is valid when `set_or_clear` is set to `ES_SET`
 * @field set The acl_t structure to be used by various acl(3) functions
 *        @note The acl provided cannot be directly used by functions within
 *        the <sys/acl.h> header. These functions can mutate the struct passed
 *        into them, which is not compatible with the immutable nature of
 *        Es_message_t. Additionally, because this field is minimally constructed,
 *        you must not use `acl_dup(3)` to get a mutable copy, as this can lead to
 *        out of bounds memory access. To obtain a acl_t struct that is able to be
 *        used with all functions within <sys/acl.h>, please use a combination of
 *        `acl_copy_ext(3)` followed by `acl_copy_int(3)`.
 * @field target Describes the file whose ACL is being set.
 *
 * @note This event type does not support caching.
 */
type Es_event_setacl_t struct {
	target       *Es_file_t
	set_or_clear Es_set_or_clear_t
	acl          struct{}
	reserved     [64]uint8
}

/**
 * @brief Fired when a pseudoterminal control device is granted
 *
 * @field dev Major and minor numbers of device
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_pty_grant_t struct {
	dev      uint32
	reserved [64]uint8
}

/**
 * @brief Fired when a pseudoterminal control device is closed
 *
 * @field dev Major and minor numbers of device
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_pty_close_t struct {
	dev      uint32
	reserved [64]uint8
}

/**
 * @brief Access control check for retrieving process information.
 *
 * @field target The process for which the access will be checked
 * @field type The type of call number used to check the access on the target process
 * @field flavor The flavor used to check the access on the target process
 *
 * @note Cache key for this event type:  (process executable file, target process executable file, type)
 */
type Es_event_proc_check_t struct {
	target   *Es_process_t
	type_    Es_proc_check_type_t
	flavor   int
	reserved [64]uint8
}

/**
 * @brief Access control check for searching a volume or a mounted file system
 *
 * @field attrlist The attributes that will be used to do the search
 * @field target The volume whose contents will be searched
 *
 * @note Cache key for this event type:  (process executable file, target file)
 */
type Es_event_searchfs_t struct {
	attrlist struct{}
	target   *Es_file_t
	reserved [64]uint8
}

/**
 * @brief This enum describes the type of suspend/resume operations that are currently used.
 */
type Es_proc_suspend_resume_type_t int

const (
	ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND Es_proc_suspend_resume_type_t = iota
	ES_PROC_SUSPEND_RESUME_TYPE_RESUME
	ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS
)

/**
 * @brief Fired when one of pid_suspend, pid_resume or pid_shutdown_sockets
 * is called on a process.
 *
 * @field target The process that is being suspended, resumed, or is the object
 * of a pid_shutdown_sockets call.
 * @field type The type of operation that was called on the target process.
 *
 * @note This event type does not support caching.
 */
type Es_event_proc_suspend_resume_t struct {
	target   *Es_process_t
	type_    Es_proc_suspend_resume_type_t
	reserved [64]uint8
}

/**
 * @brief Code signing status for process was invalidated.
 *
 * @note This event fires when the CS_VALID bit is removed from a
 * process' CS flags, that is, when the first invalid page is paged in
 * for a process with an otherwise valid code signature, or when a
 * process is explicitly invalidated by a csops(CS_OPS_MARKINVALID)
 * syscall.  This event does not fire if CS_HARD was set, since CS_HARD
 * by design prevents the process from going invalid.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_cs_invalidated_t struct {
	reserved [64]uint8
}

/**
 * @brief Fired when one process attempts to attach to another process
 *
 * @field target The process that will be attached to by the process
 * that instigated the event
 *
 * @note This event can fire multiple times for a single trace attempt, for example
 * when the processes to which is being attached is reparented during the operation
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_trace_t struct {
	target   *Es_process_t
	reserved [64]uint8
}

/**
 * @brief Notification that a process has attempted to create a thread in
 * another process by calling one of the thread_create or thread_create_running
 * MIG routines.
 *
 * @field target The process in which a new thread was created
 * @field thread_state The new thread state in case of thread_create_running,
 * NULL in case of thread_create.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_remote_thread_create_t struct {
	target       *Es_process_t
	thread_state *Es_thread_state_t
	reserved     [64]uint8
}

/**
 * @brief Notification that a process has called setuid().
 *
 * @field uid The uid argument to the setuid() syscall.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_setuid_t struct {
	uid      uint32
	reserved [64]uint8
}

/**
 * @brief Notification that a process has called setgid().
 *
 * @field gid The gid argument to the setgid() syscall.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_setgid_t struct {
	gid      uint32
	reserved [64]uint8
}

/**
 * @brief Notification that a process has called seteuid().
 *
 * @field euid The euid argument to the seteuid() syscall.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_seteuid_t struct {
	euid     uint32
	reserved [64]uint8
}

/**
 * @brief Notification that a process has called setegid().
 *
 * @field egid The egid argument to the setegid() syscall.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_setegid_t struct {
	egid     uint32
	reserved [64]uint8
}

/**
 * @brief Notification that a process has called setreuid().
 *
 * @field ruid The ruid argument to the setreuid() syscall.
 * @field euid The euid argument to the setreuid() syscall.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_setreuid_t struct {
	ruid     uint32
	euid     uint32
	reserved [64]uint8
}

/**
 * @brief Notification that a process has called setregid().
 *
 * @field rgid The rgid argument to the setregid() syscall.
 * @field egid The egid argument to the setregid() syscall.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_setregid_t struct {
	rgid     uint32
	egid     uint32
	reserved [64]uint8
}

/**
 * @brief OpenDirectory authentication data for type ES_AUTHENTICATION_TYPE_OD.
 *
 * @field instigator        Process that instigated the authentication
 *                          (XPC caller that asked for authentication).
 * @field record_type       OD record type against which OD is authenticating.
 *                          Typically "Users", but other record types can auth too.
 * @field record_name       OD record name against which OD is authenticating.
 *                          For record type "Users", this is the username.
 * @field node_name         OD node against which OD is authenticating.
 *                          Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                          "/Active Directory/<domain>".
 * @field db_path           Optional.  If node_name is "/Local/Default", this is
 *                          the path of the database against which OD is
 *                          authenticating.
 */
type Es_event_authentication_od_t struct {
	instigator  *Es_process_t
	record_type Es_string_token_t
	record_name Es_string_token_t
	node_name   Es_string_token_t
	db_path     Es_string_token_t
}

type Es_touchid_mode_t int

const (
	ES_TOUCHID_MODE_VERIFICATION Es_touchid_mode_t = iota
	ES_TOUCHID_MODE_IDENTIFICATION
)

/**
 * @brief TouchID authentication data for type ES_AUTHENTICATION_TYPE_TOUCHID.
 *
 * @field instigator        Process that instigated the authentication
 *                          (XPC caller that asked for authentication).
 * @field touchid_mode      TouchID authentication type
 * @field has_uid           Describes whether or not the uid of the user authenticated is available
 * @field uid               Union that is valid when `has_uid` is set to `true`
 * @field uid.uid           uid of user that was authenticated.
 *                          This will be set when `success` is true and `touchid_mode` is of
 *                          verification type i.e. ES_TOUCHID_MODE_VERIFICATION
 */
type Es_event_authentication_touchid_t struct {
	instigator   *Es_process_t
	touchid_mode Es_touchid_mode_t
	has_uid      bool
	uid          uint32
}

/**
 * @brief Token authentication data for type ES_AUTHENTICATION_TYPE_TOKEN.
 *
 * @field instigator        Process that instigated the authentication
 *                          (XPC caller that asked for authentication).
 * @field pubkey_hash       Hash of the public key which CryptoTokenKit is authenticating.
 * @field token_id          Token identifier of the event which CryptoTokenKit is authenticating.
 * @field kerberos_principal Optional.  This will be available if token is used for GSS PKINIT
 *                          authentication for obtaining a kerberos TGT.  NULL in all other cases.
 */
type Es_event_authentication_token_t struct {
	instigator         *Es_process_t
	pubkey_hash        Es_string_token_t
	token_id           Es_string_token_t
	kerberos_principal Es_string_token_t
}

type Es_auto_unlock_type_t int

const (
	ES_AUTO_UNLOCK_MACHINE_UNLOCK Es_auto_unlock_type_t = iota + 1
	ES_AUTO_UNLOCK_AUTH_PROMPT
)

/**
 * @brief Auto Unlock authentication data for type ES_AUTHENTICATION_TYPE_TOKEN.
 *
 * @field username          Username for which the authentication was attempted.
 * @field type              Purpose of the authentication.
 *
 * @note This kind of authentication is performed when authenticating to the local
 * Mac using an Apple Watch for the purpose of unlocking the machine or confirming
 * an authorization prompt.  Auto Unlock is part of Continuity.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_authentication_auto_unlock_t struct {
	username string
	typ      Es_auto_unlock_type_t
}

/**
 * @brief Notification that an authentication was performed.
 *
 * @field success           True iff authentication was successful.
 * @field type              The type of authentication.
 * @field data              Type-specific data describing the authentication.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_authentication_t struct {
	success bool
	typ     Es_authentication_type_t
	data    struct {
		od          *Es_event_authentication_od_t
		touchid     *Es_event_authentication_touchid_t
		token       *Es_event_authentication_token_t
		auto_unlock *Es_event_authentication_auto_unlock_t
	}
}

/**
 * @brief Notification that XProtect detected malware.
 *
 * @field signature_version     Version of the signatures used for detection.
 *                              Currently corresponds to XProtect version.
 * @field malware_identifier    String identifying the malware that was detected.
 * @field incident_identifier   String identifying the incident, intended for linking
 *                              multiple malware detected and remediated events.
 * @field detected_path         Path where malware was detected.  This path is not
 *                              necessarily a malicious binary, it can also be a
 *                              legitimate file containing a malicious portion.
 *
 * @note For any given malware incident, XProtect may emit zero or more
 *       xp_malware_detected events, and zero or more xp_malware_remediated events.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_xp_malware_detected_t struct {
	signature_version   Es_string_token_t
	malware_identifier  Es_string_token_t
	incident_identifier Es_string_token_t
	detected_path       Es_string_token_t
}

/**
 * @brief Notification that XProtect remediated malware.
 *
 * @field signature_version     Version of the signatures used for remediation.
 *                              Currently corresponds to XProtect version.
 * @field malware_identifier    String identifying the malware that was detected.
 * @field incident_identifier   String identifying the incident, intended for linking
 *                              multiple malware detected and remediated events.
 * @field action_type           String indicating the type of action that was taken,
 *                              e.g. "path_delete".
 * @field success               True iff remediation was successful.
 * @field result_description    String describing specific reasons for failure or success.
 * @field remediated_path       Optional.  Path that was subject to remediation, if any.
 *                              This path is not necessarily a malicious binary, it can
 *                              also be a legitimate file containing a malicious portion.
 *                              Specifically, the file at this path may still exist after
 *                              successful remediation.
 * @field remediated_process_audit_token  Audit token of process that was subject to
 *                              remediation, if any.
 *
 * @note For any given malware incident, XProtect may emit zero or more
 *       xp_malware_detected events, and zero or more xp_malware_remediated events.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_xp_malware_remediated_t struct {
	signature_version              Es_string_token_t
	malware_identifier             Es_string_token_t
	incident_identifier            Es_string_token_t
	action_type                    Es_string_token_t
	success                        bool
	result_description             Es_string_token_t
	remediated_path                Es_string_token_t
	remediated_process_audit_token *audit_token_t
}

/**
 * @brief es_graphical_session_id_t is a session identifier identifying a on-console or off-console graphical session.
 * A graphical session exists and can potentially be attached to via Screen Sharing before a user is logged in.
 * EndpointSecurity clients should treat the `graphical_session_id` as an opaque identifier and not assign
 * special meaning to it beyond correlating events pertaining to the same graphical session.  Not to be confused with the audit session ID.
 */
type Es_graphical_session_id_t uint32

/**
 * @brief Notification that LoginWindow has logged in a user.
 *
 * @field username              Short username of the user.
 * @field graphical_session_id  Graphical session id of the session.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_lw_session_login_t struct {
	username             Es_string_token_t
	graphical_session_id Es_graphical_session_id_t
}

/**
 * @brief Notification that LoginWindow has logged out a user.
 *
 * @field username              Short username of the user.
 * @field graphical_session_id  Graphical session id of the session.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_lw_session_logout_t struct {
	username             Es_string_token_t
	graphical_session_id Es_graphical_session_id_t
}

/**
 * @brief Notification that LoginWindow locked the screen of a session.
 *
 * @field username              Short username of the user.
 * @field graphical_session_id  Graphical session id of the session.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_lw_session_lock_t struct {
	username             Es_string_token_t
	graphical_session_id Es_graphical_session_id_t
}

/**
 * @brief Notification that LoginWindow unlocked the screen of a session.
 *
 * @field username              Short username of the user.
 * @field graphical_session_id  Graphical session id of the session.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_lw_session_unlock_t struct {
	username             Es_string_token_t
	graphical_session_id Es_graphical_session_id_t
}

/**
 * @brief Notification that Screen Sharing has attached to a graphical session.
 *
 * @field success               True iff Screen Sharing successfully attached.
 * @field source_address_type   Type of source address.
 * @field source_address        Optional.  Source address of connection, or NULL.
 *                              Depending on the transport used, the source
 *                              address may or may not be available.
 * @field viewer_appleid        Optional.  For screen sharing initiated using an
 *                              Apple ID (e.g., from Messages or FaceTime), this
 *                              is the viewer's (client's) Apple ID.  It is not
 *                              necessarily the Apple ID that invited the screen
 *                              sharing.  NULL if unavailable.
 * @field authentication_type   Type of authentication.
 * @field authentication_username  Optional.  Username used for authentication to
 *                              Screen Sharing.  NULL if authentication type doesn't
 *                              use an username (e.g. simple VNC password).
 * @field session_username      Optional.  Username of the loginwindow session if
 *                              available,  NULL otherwise.
 * @field existing_session      True iff there was an existing user session.
 * @field graphical_session_id  Graphical session id of the screen shared.
 *
 * @note This event type does not support caching (notify-only).
 * @discussion This event is not emitted when a screensharing session has the same source and destination address.
 * For example if device A is acting as a NAT gateway for device B, then a screensharing session from B -> A would not emit an event.
 */
type Es_event_screensharing_attach_t struct {
	success                 bool
	source_address_type     Es_address_type_t
	source_address          Es_string_token_t
	viewer_appleid          Es_string_token_t
	authentication_type     Es_string_token_t
	authentication_username Es_string_token_t
	session_username        Es_string_token_t
	existing_session        bool
	graphical_session_id    Es_graphical_session_id_t
}

/**
 * @brief Notification that Screen Sharing has detached from a graphical session.
 *
 * @field source_address_type   Type of source address.
 * @field source_address        Optional.  Source address of connection, or NULL.
 *                              Depending on the transport used, the source
 *                              address may or may not be available.
 * @field viewer_appleid        Optional.  For screen sharing initiated using an
 *                              Apple ID (e.g., from Messages or FaceTime), this
 *                              is the viewer's (client's) Apple ID.  It is not
 *                              necessarily the Apple ID that invited the screen
 *                              sharing.  NULL if unavailable.
 * @field graphical_session_id  Graphical session id of the screen shared.
 *
 * @note This event type does not support caching (notify-only).
 * @discussion This event is not emitted when a screensharing session has the same source and destination address.
 */
type Es_event_screensharing_detach_t struct {
	source_address_type  Es_address_type_t
	source_address       Es_string_token_t
	viewer_appleid       Es_string_token_t
	graphical_session_id Es_graphical_session_id_t
}

type Es_openssh_login_result_type_t int

const (
	ES_OPENSSH_LOGIN_EXCEED_MAXTRIES Es_openssh_login_result_type_t = iota
	ES_OPENSSH_LOGIN_ROOT_DENIED
	ES_OPENSSH_AUTH_SUCCESS
	ES_OPENSSH_AUTH_FAIL_NONE
	ES_OPENSSH_AUTH_FAIL_PASSWD
	ES_OPENSSH_AUTH_FAIL_KBDINT
	ES_OPENSSH_AUTH_FAIL_PUBKEY
	ES_OPENSSH_AUTH_FAIL_HOSTBASED
	ES_OPENSSH_AUTH_FAIL_GSSAPI
	ES_OPENSSH_INVALID_USER
)

/**
 * @brief Notification for OpenSSH login event.
 *
 * @field success               True iff login was successful.
 * @field result_type           Result type for the login attempt.
 * @field source_address_type   Type of source address.
 * @field source_address        Source address of connection.
 * @field username              Username used for login.
 * @field has_uid               Describes whether or not the uid of the user logged in is available
 * @field uid                   Union that is valid when `has_uid` is set to `true`
 * @field uid.uid               uid of user that was logged in.
 *
 * @note This is a connection-level event.  An SSH connection that is used
 * for multiple interactive sessions and/or non-interactive commands will
 * emit only a single successful login event.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_openssh_login_t struct {
	success             bool
	result_type         Es_openssh_login_result_type_t
	source_address_type Es_address_type_t
	source_address      Es_string_token_t
	username            Es_string_token_t
	has_uid             bool
	uid                 uint32
}

/**
 * @brief Notification for OpenSSH logout event.
 *
 * @field source_address_type   Type of address used in the connection.
 * @field source_address        Source address of the connection.
 * @field username              Username which got logged out.
 * @field uid                   uid of user that was logged out.
 *
 * @note This is a connection-level event.  An SSH connection that is used
 * for multiple interactive sessions and/or non-interactive commands will
 * emit only a single logout event.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_openssh_logout_t struct {
	success             bool
	result_type         Es_openssh_login_result_type_t
	source_address_type Es_address_type_t
	source_address      Es_string_token_t
	username            Es_string_token_t
	uid                 uint32
}

/**
 * @brief Notification for authenticated login event from /usr/bin/login.
 *
 * @field success               True iff login was successful.
 * @field failure_message       Optional. Failure message generated.
 * @field username              Username used for login.
 * @field has_uid               Describes whether or not the uid of the user logged in is available or not.
 * @field uid                   Union that is valid when `has_uid` is set to `true`
 * @field uid.uid               uid of user that was logged in.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_login_login_t struct {
	success         bool
	failure_message Es_string_token_t
	username        Es_string_token_t
	has_uid         bool
	uid             uint32
}

/**
 * @brief Notification for authenticated logout event from /usr/bin/login.
 *
 * @field username              Username used for login.
 * @field uid                   uid of user that was logged in.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_login_logout_t struct {
	username Es_string_token_t
	uid      uint32
}

/**
 * @brief Notification for launch item being made known to background
 *        task management.  This includes launch agents and daemons as
 *        well as login items added by the user, via MDM or by an app.
 *
 * @field instigator            Optional.  Process that instigated the BTM operation
 *                              (XPC caller that asked for the item to be added).
 * @field app                   Optional.  App process that registered the item.
 * @field item                  BTM launch item.
 * @field executable_path       Optional.  If available and applicable, the POSIX executable
 *                              path from the launchd plist.
 *                              If the path is relative, it is relative to item->app_url.
 *
 * @note May be emitted for items where an add was already seen previously,
 *       with or without the item having changed.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_btm_launch_item_add_t struct {
	instigator *Es_process_t
	is_update  bool
	profile    *Es_profile_t
}

/**
 * @brief Notification for launch item being removed from background
 *        task management.  This includes launch agents and daemons as
 *        well as login items added by the user, via MDM or by an app.
 *
 * @field instigator            Optional.  Process that instigated the BTM operation
 *                              (XPC caller that asked for the item to be removed).
 * @field app                   Optional.  App process that registered the item.
 * @field item                  BTM launch item.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_btm_launch_item_remove_t struct {
	instigator *Es_process_t
	app        *Es_process_t
	item       *Es_btm_launch_item_t
}

/**
 * @brief Notification for a su policy decisions events.
 *
 * @field success           True iff su was successful.
 * @field failure_message   Optional. If success is false, a failure message is contained in this field
 * @field from_uid          The uid of the user who initiated the su
 * @field from_name         The name of the user who initiated the su
 * @field has_to_uid        True iff su was successful, Describes whether or not the to_uid is interpretable
 * @field to_uid            Optional. If success, the user ID that is going to be substituted
 * @field to_username       Optional. If success, the user name that is going to be substituted
 * @field shell             Optional. If success, the shell is going to execute
 * @field argc              The length of argv
 * @field argv              If success, the arguments are passed into to the shell
 * @field env_count         The length of env
 * @field env               If success, list of environment variables that is going to be substituted
 *
 * @note This event type does not support caching (notify-only). Should always
 * emit on success but will only emit on security relevant failures. For example,
 * Endpoint Security clients will not get an event for su being passed invalid
 * command line arguments.
 *
 */
type Es_event_su_t struct {
	success         bool
	failure_message Es_string_token_t
	from_uid        uint32
	from_username   Es_string_token_t
	has_to_uid      bool
	to_uid          uint32
	to_username     Es_string_token_t
	shell           Es_string_token_t
	argc            int
	argv            []Es_string_token_t
	env_count       int
	env             []Es_string_token_t
}

type Es_sudo_plugin_type_t int

const (
	ES_SUDO_PLUGIN_TYPE_UNKNOWN Es_sudo_plugin_type_t = iota
	ES_SUDO_PLUGIN_TYPE_FRONT_END
	ES_SUDO_PLUGIN_TYPE_POLICY
	ES_SUDO_PLUGIN_TYPE_IO
	ES_SUDO_PLUGIN_TYPE_AUDIT
	ES_SUDO_PLUGIN_TYPE_APPROVAL
)

/**
 * @brief Provides context about failures in es_event_sudo_t.
 *
 * @field plugin_name      The sudo plugin that initiated the reject
 * @field plugin_type      The sudo plugin type that initiated the reject
 * @field failure_message  A reason represented by a string for the failure
 *
 */
type Es_sudo_reject_info_t struct {
	plugin_name     Es_string_token_t
	plugin_type     Es_sudo_plugin_type_t
	failure_message Es_string_token_t
}

/**
 * @brief Notification for a sudo event.
 *
 * @field success          True iff sudo was successful
 * @field reject_info      Optional. When success is false, describes why sudo was rejected
 * @field has_from_uid     Describes whether or not the from_uid is interpretable
 * @field from_uid         Optional. The uid of the user who initiated the su
 * @field from_name        Optional. The name of the user who initiated the su
 * @field has_to_uid       Describes whether or not the to_uid is interpretable
 * @field to_uid           Optional. If success, the user ID that is going to be substituted
 * @field to_username      Optional. If success, the user name that is going to be substituted
 * @field command          Optional. The command to be run
 *
 * @note This event type does not support caching (notify-only).
 *
 */

type Es_event_sudo_t struct {
	success       bool
	reject_info   *Es_sudo_reject_info_t
	from_uid      uint32
	from_username Es_string_token_t
	has_to_uid    bool
	to_uid        uint32
	to_username   Es_string_token_t
	command       Es_string_token_t
}

/**
 * @brief Notification for Profiles installed on the system.
 *
 * @field instigator            Process that instigated the Profile install or update.
 * @field is_update             Indicates if the profile is an update to an already installed
 * 								profile.
 * @field item                  Profile install item.
 *
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_profile_add_t struct {
	instigator *Es_process_t
	is_update  bool
	profile    *Es_profile_t
}

/**
 * @brief Notification for Profiles removed on the system.
 * @field instigator            Process that instigated the Profile removal.
 * @field item                  Profile being removed.
 *
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_profile_remove_t struct {
	instigator *Es_process_t
	profile    *Es_profile_t
}

/**
 * @brief Notification that a process peititioned for certain authorization rights
 *
 * @field instigator            Process that submitted the petition (XPC caller)
 * @field petitioner            Process that created the petition
 * @field flags                 Flags associated with the petition. Defined Security framework "Authorization/Authorizatioh.h"
 * @field right_count           The number of elements in `rights`
 * @field rights                Array of string tokens, each token is the name of a right being requested
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_authorization_petition_t struct {
	instigator *Es_process_t
	petitioner *Es_process_t
	flags      uint32
	rights     []Es_string_token_t
}

/**
 * @brief Describes, for a single right, the class of that right and if it was granted
 *
 * @field right_name            The name of the right being considered
 * @field rule_class            The class of the right being considered
 *                              The rule class determines how the operating system determines
 *                              if it should be granted or not
 * @field granted               Indicates if the right was granted or not
 */
type Es_authorization_result_t struct {
	right_name string
	rule_class Es_authorization_rule_class_t
	granted    bool
}

/**
 * @brief Notification that a process had it's right petition judged
 *
 * @field instigator            Process that submitted the petition (XPC caller)
 * @field petitioner            Process that created the petition
 * @field return_code           The overall result of the petition. 0 indicates success.
 *                              Possible return codes are defined Security framework "Authorization/Authorizatioh.h"
 * @field result_count          The number of elements in `results`
 * @field results               Array of results. One for each right that was peititioned
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_authorization_judgement_t struct {
	instigator  *Es_process_t
	petitioner  *Es_process_t
	return_code int
	results     []Es_authorization_result_t
}

/**
 * @brief The identity of a group member
 *
 * @field member_type    Indicates the type of the member, and how it is identified.
 *                       Note that member_type indicates which field of member_value is initialised.
 * @field member_value   The member identity.
 */
type Es_od_member_id_t struct {
	member_type Es_od_member_type_t
	uuid        uuid_t
	name        Es_string_token_t
}

/**
 * @brief Notification that a member was added to a group.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field group_name   The group to which the member was added.
 * @field member       The identity of the member added.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note This event does not indicate that a member was actually added.
 *       For example when adding a user to a group they are already a member of.
 */
type Es_event_od_group_add_t struct {
	instigator *Es_process_t
	error_code int
	group_name Es_string_token_t
	member     *Es_od_member_id_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification that a member was removed from a group.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field group_name   The group from which the member was removed.
 * @field member       The identity of the member removed.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note This event does not indicate that a member was actually removed.
 *       For example when removing a user from a group they are not a member of.
 */
type Es_event_od_group_remove_t struct {
	instigator *Es_process_t
	error_code int
	group_name Es_string_token_t
	member     *Es_od_member_id_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief An array of group member identities.
 *
 * @field member_type    Indicates the type of the members, and how they are identified.
 *                       Note that member_type indicates which field of member_array is initialised.
 * @field member_count   The number of elements in member_array.
 * @field member_array   A union of pointers.
 *                       The initialised member points to the first element of an array of member values.
 */
type Es_od_member_id_array_t struct {
	member_type  Es_od_member_type_t
	member_count int
	uuid         uuid_t
	name         Es_string_token_t
}

/**
 * @brief Notification that a group had it's members initialised or replaced.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field group_name   The group for which members were set.
 * @field members      Array of new members.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note This event does not indicate that a member was actually removed.
 *       For example when removing a user from a group they are not a member of.
 */
type Es_event_od_group_set_t struct {
	instigator *Es_process_t
	error_code int
	group_name Es_string_token_t
	members    *Es_od_member_id_array_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification that an account had its password modified.
 *
 * @field instigator     Process that instigated operation (XPC caller).
 * @field error_code     0 indicates the operation succeeded.
 *                       Values inidicating specific failure reasons are defined in odconstants.h.
 * @field account_type   The type of the account for which the password was modified.
 * @field account_name   The name of the account for which the password was modified.
 * @field node_name      OD node being mutated.
 *                       Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                       "/Active Directory/<domain>".
 * @field db_path        Optional.  If node_name is "/Local/Default", this is
 *                       the path of the database against which OD is
 *                       authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_od_modify_password_t struct {
	instigator   *Es_process_t
	error_code   int
	account_type Es_od_account_type_t
	account_name Es_string_token_t
	node_name    Es_string_token_t
	db_path      Es_string_token_t
}

/**
 * @brief Notification that a user account was disabled.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field user_name    The name of the user account that was disabled.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_od_disable_user_t struct {
	instigator *Es_process_t
	error_code int
	user_name  Es_string_token_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification that a user account was enabled.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field user_name    The name of the user account that was enabled.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_od_enable_user_t struct {
	instigator *Es_process_t
	error_code int
	user_name  Es_string_token_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification that an attribute value was added to a record.
 *
 * @field instigator       Process that instigated operation (XPC caller).
 * @field error_code       0 indicates the operation succeeded.
 *                         Values inidicating specific failure reasons are defined in odconstants.h.
 * @field record_type      The type of the record to which the attribute value was added.
 * @field record_name      The name of the record to which the attribute value was added.
 * @field attribute_name   The name of the attribute to which the value was added.
 * @field attribute_value  The value that was added.
 * @field node_name        OD node being mutated.
 *                         Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                         "/Active Directory/<domain>".
 * @field db_path          Optional.  If node_name is "/Local/Default", this is
 *                         the path of the database against which OD is
 *                         authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note Attributes conceptually have the type `Map String (Set String)`.
 *       Each OD record has a Map of attribute name to Set of attribute value.
 *       When an attribute value is added, it is inserted into the set of values for that name.
 */
type Es_event_od_attribute_value_add_t struct {
	instigator      *Es_process_t
	error_code      int
	record_type     Es_od_record_type_t
	record_name     Es_string_token_t
	attribute_name  Es_string_token_t
	attribute_value Es_string_token_t
	node_name       Es_string_token_t
	db_path         Es_string_token_t
}

/**
 * @brief Notification that an attribute value was removed from a record.
 *
 * @field instigator       Process that instigated operation (XPC caller).
 * @field error_code       0 indicates the operation succeeded.
 *                         Values inidicating specific failure reasons are defined in odconstants.h.
 * @field record_type      The type of the record from which the attribute value was removed.
 * @field record_name      The name of the record from which the attribute value was removed.
 * @field attribute_name   The name of the attribute from which the value was removed.
 * @field attribute_value  The value that was removed.
 * @field node_name        OD node being mutated.
 *                         Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                         "/Active Directory/<domain>".
 * @field db_path          Optional.  If node_name is "/Local/Default", this is
 *                         the path of the database against which OD is
 *                         authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note Attributes conceptually have the type `Map String (Set String)`.
 *       Each OD record has a Map of attribute name to Set of attribute value.
 *       When an attribute value is removed, it is subtraced from the set of values for that name.
 * @note Removing a value that was never added is a no-op.
 */
type Es_event_od_attribute_value_remove_t struct {
	instigator      *Es_process_t
	error_code      int
	record_type     Es_od_record_type_t
	record_name     Es_string_token_t
	attribute_name  Es_string_token_t
	attribute_value Es_string_token_t
	node_name       Es_string_token_t
	db_path         Es_string_token_t
}

/**
 * @brief Notification that an attribute is being set.
 *
 * @field instigator              Process that instigated operation (XPC caller).
 * @field error_code              0 indicates the operation succeeded.
 *                                Values inidicating specific failure reasons are defined in odconstants.h.
 * @field record_type             The type of the record for which the attribute is being set.
 * @field record_name             The name of the record for which the attribute is being set.
 * @field attribute_name          The name of the attribute that was set.
 * @field attribute_value_count   The size of attribute_value_array.
 * @field attribute_value_array   Array of attribute values that were set.
 * @field node_name               OD node being mutated.
 *                                Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                                "/Active Directory/<domain>".
 * @field db_path                 Optional.  If node_name is "/Local/Default", this is
 *                                the path of the database against which OD is
 *                                authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note Attributes conceptually have the type `Map String (Set String)`.
 *       Each OD record has a Map of attribute name to Set of attribute value.
 *       An attribute set operation indicates the entire set of attribute values was replaced.
 * @note The new set of attribute values may be empty.
 */
type Es_event_od_attribute_set_t struct {
	instigator       *Es_process_t
	error_code       int
	record_type      Es_od_record_type_t
	record_name      Es_string_token_t
	attribute_name   Es_string_token_t
	attribute_values []Es_string_token_t
	node_name        Es_string_token_t
	db_path          Es_string_token_t
}

/**
 * @brief Notification that a user account was created.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field user_name    The name of the user account that was created.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_od_create_user_t struct {
	instigator *Es_process_t
	error_code int
	user_name  Es_string_token_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification that a group was created.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field user_name    The name of the group that was created.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_od_create_group_t struct {
	instigator *Es_process_t
	error_code int
	group_name Es_string_token_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification that a user account was deleted.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field user_name    The name of the user account that was deleted.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_od_delete_user_t struct {
	instigator *Es_process_t
	error_code int
	user_name  Es_string_token_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification that a group was deleted.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field user_name    The name of the group that was deleted.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_od_delete_group_t struct {
	instigator *Es_process_t
	error_code int
	group_name Es_string_token_t
	node_name  Es_string_token_t
	db_path    Es_string_token_t
}

/**
 * @brief Notification for an XPC connection being established to a named service.
 *
 * @field service_name          Service name of the named service.
 * @field service_domain_type   The type of XPC domain in which the service resides in.
 *
 * @note This event type does not support caching (notify-only).
 */
type Es_event_xpc_connect_t struct {
	service_name        Es_string_token_t
	service_domain_type Es_xpc_domain_type_t
}

/**
 * Union of all possible events that can appear in an es_message_t
 */
type Es_events_t struct {
	access                    Es_event_access_t
	chdir                     Es_event_chdir_t
	chroot                    Es_event_chroot_t
	clone                     Es_event_clone_t
	close                     Es_event_close_t
	copyfile                  Es_event_copyfile_t
	create                    Es_event_create_t
	cs_invalidated            Es_event_cs_invalidated_t
	deleteextattr             Es_event_deleteextattr_t
	dup                       Es_event_dup_t
	exchangedata              Es_event_exchangedata_t
	exec                      Es_event_exec_t
	exit                      Es_event_exit_t
	file_provider_materialize Es_event_file_provider_materialize_t
	file_provider_update      Es_event_file_provider_update_t
	fcntl                     Es_event_fcntl_t
	fork                      Es_event_fork_t
	fsgetpath                 Es_event_fsgetpath_t
	get_task                  Es_event_get_task_t
	get_task_read             Es_event_get_task_read_t
	get_task_inspect          Es_event_get_task_inspect_t
	get_task_name             Es_event_get_task_name_t
	getattrlist               Es_event_getattrlist_t
	getextattr                Es_event_getextattr_t
	iokit_open                Es_event_iokit_open_t
	kextload                  Es_event_kextload_t
	kextunload                Es_event_kextunload_t
	link                      Es_event_link_t
	listextattr               Es_event_listextattr_t
	lookup                    Es_event_lookup_t
	mmap                      Es_event_mmap_t
	mount                     Es_event_mount_t
	mprotect                  Es_event_mprotect_t
	open                      Es_event_open_t
	proc_check                Es_event_proc_check_t
	proc_suspend_resume       Es_event_proc_suspend_resume_t
	pty_close                 Es_event_pty_close_t
	pty_grant                 Es_event_pty_grant_t
	readdir                   Es_event_readdir_t
	readlink                  Es_event_readlink_t
	remote_thread_create      Es_event_remote_thread_create_t
	remount                   Es_event_remount_t
	rename                    Es_event_rename_t
	searchfs                  Es_event_searchfs_t
	setacl                    Es_event_setacl_t
	setattrlist               Es_event_setattrlist_t
	setextattr                Es_event_setextattr_t
	setflags                  Es_event_setflags_t
	setmode                   Es_event_setmode_t
	setowner                  Es_event_setowner_t
	settime                   Es_event_settime_t
	setuid                    Es_event_setuid_t
	setgid                    Es_event_setgid_t
	seteuid                   Es_event_seteuid_t
	setegid                   Es_event_setegid_t
	setreuid                  Es_event_setreuid_t
	setregid                  Es_event_setregid_t
	signal                    Es_event_signal_t
	stat                      Es_event_stat_t
	trace                     Es_event_trace_t
	truncate                  Es_event_truncate_t
	uipc_bind                 Es_event_uipc_bind_t
	uipc_connect              Es_event_uipc_connect_t
	unlink                    Es_event_unlink_t
	unmount                   Es_event_unmount_t
	utimes                    Es_event_utimes_t
	write                     Es_event_write_t
	//
	// Events added in macOS 13.0 or later use nonnull pointers.
	//
	authentication            *Es_event_authentication_t
	xp_malware_detected       *Es_event_xp_malware_detected_t
	xp_malware_remediated     *Es_event_xp_malware_remediated_t
	lw_session_login          *Es_event_lw_session_login_t
	lw_session_logout         *Es_event_lw_session_logout_t
	lw_session_lock           *Es_event_lw_session_lock_t
	lw_session_unlock         *Es_event_lw_session_unlock_t
	screensharing_attach      *Es_event_screensharing_attach_t
	screensharing_detach      *Es_event_screensharing_detach_t
	openssh_login             *Es_event_openssh_login_t
	openssh_logout            *Es_event_openssh_logout_t
	login_login               *Es_event_login_login_t
	login_logout              *Es_event_login_logout_t
	btm_launch_item_add       *Es_event_btm_launch_item_add_t
	btm_launch_item_remove    *Es_event_btm_launch_item_remove_t
	profile_add               *Es_event_profile_add_t
	profile_remove            *Es_event_profile_remove_t
	su                        *Es_event_su_t
	authorization_petition    *Es_event_authorization_petition_t
	authorization_judgement   *Es_event_authorization_judgement_t
	sudo                      *Es_event_sudo_t
	od_group_add              *Es_event_od_group_add_t
	od_group_remove           *Es_event_od_group_remove_t
	od_group_set              *Es_event_od_group_set_t
	od_modify_password        *Es_event_od_modify_password_t
	od_disable_user           *Es_event_od_disable_user_t
	od_enable_user            *Es_event_od_enable_user_t
	od_attribute_value_add    *Es_event_od_attribute_value_add_t
	od_attribute_value_remove *Es_event_od_attribute_value_remove_t
	od_attribute_set          *Es_event_od_attribute_set_t
	od_create_user            *Es_event_od_create_user_t
	od_create_group           *Es_event_od_create_group_t
	od_delete_user            *Es_event_od_delete_user_t
	od_delete_group           *Es_event_od_delete_group_t
	xpc_connect               *Es_event_xpc_connect_t
}

/**
 * es_result_t indicates the result of the ES subsystem authorization process
 * The result_type field indicates if the result is an es_auth_result_t or a uint32_t (flags)
 */
type Es_result_t struct {
	result_type Es_result_type_t
	result      interface{}
}

/**
 * @brief es_message_t is the top level datatype that encodes information sent
 * from the ES subsystem to its clients.  Each security event being processed
 * by the ES subsystem will be encoded in an es_message_t.  A message can be an
 * authorization request or a notification of an event that has already taken
 * place.
 *
 * @field version Indicates the message version; some fields are not available
 *        and must not be accessed unless the message version is equal to or
 *        higher than the message version at which the field was introduced.
 * @field time The time at which the event was generated.
 * @field mach_time The Mach absolute time at which the event was generated.
 * @field deadline The Mach absolute time before which an auth event must
 *        be responded to. If a client fails to respond to auth events prior to the `deadline`,
 *        the client will be killed.
 *        Each message can contain its own unique deadline, and some deadlines
 *        can vary substantially. Clients must take care to inspect the deadline
 *        value of each message to know how much time is allotted for processing.
 * @field process Describes the process that took the action.
 * @field seq_num Per-client, per-event-type sequence number that can be
 *        inspected to detect whether the kernel had to drop events for this
 *        client.  When no events are dropped for this client, seq_num
 *        increments by 1 for every message of that event type.  When events
 *        have been dropped, the difference between the last seen sequence
 *        number of that event type plus 1 and seq_num of the received message
 *        indicates the number of events that had to be dropped.
 *        Dropped events generally indicate that more events were generated in
 *        the kernel than the client was able to handle.
 *        Field available only if message version >= 2.
 *        @see global_seq_num
 * @field action_type Indicates if the action field is an auth or notify action.
 * @field action For auth events, contains the opaque auth ID that must be
 *        supplied when responding to the event.  For notify events, describes
 *        the result of the action.
 * @field event_type Indicates which event struct is defined in the event union.
 * @field event Contains data specific to the event type.
 * @field thread Describes the thread that took the action.  May be NULL when
 *        thread is not applicable, for example for trace events that describe
 *        the traced process calling ptrace(PT_TRACE_ME) or for cs invalidated
 *        events that are a result of another process calling
 *        csops(CS_OPS_MARKINVALID).
 *        Field available only if message version >= 4.
 * @field global_seq_num Per-client sequence number that can be inspected to
 *        detect whether the kernel had to drop events for this client. When no
 *        events are dropped for this client, global_seq_num increments by 1 for
 *        every message. When events have been dropped, the difference between
 *        the last seen global sequence number and the global_seq_num of the
 *        received message indicates the number of events that had to be dropped.
 *        Dropped events generally indicate that more events were generated in
 *        the kernel than the client was able to handle.
 *        Field available only if message version >= 4.
 *        @see seq_num
 * @field opaque Opaque data that must not be accessed directly.
 *
 * @note For events that can be authorized there are unique NOTIFY and AUTH
 * event types for the same event data, eg: event.exec is the correct union
 * label for both ES_EVENT_TYPE_AUTH_EXEC and ES_EVENT_TYPE_NOTIFY_EXEC event
 * types.
 *
 * @note For fields marked only available in specific message versions, all
 * access must be guarded at runtime by checking the value of the message
 * version field, e.g.
 * ```
 * if (msg->version >= 2) {
 *     acl = msg->event.create.acl;
 * }
 * ```
 *
 * @note Fields using Mach time are in the resolution matching the ES client's
 * architecture.  This means they can be compared to mach_absolute_time() and
 * converted to nanoseconds with the help of mach_timebase_info().  Further
 * note that on Apple silicon, x86_64 clients running under Rosetta 2 will see
 * Mach times in a different resolution than native arm64 clients.  For more
 * information on differences regarding Mach time on Apple silicon and Intel-based
 * Mac computers, see "Addressing Architectural Differences in Your macOS Code":
 * https://developer.apple.com/documentation/apple_silicon/addressing_architectural_differences_in_your_macos_code
 */
type Es_message_t struct {
	version        uint32
	time           time.Time
	mach_time      uint64
	deadline       uint64
	process        *Es_process_t
	seq_num        uint64
	action_type    Es_action_type_t
	action         interface{}
	event_type     Es_event_type_t
	event          Es_events_t
	thread         *Es_thread_t
	global_seq_num uint64
	opaque         []uint64
}

/**
 * Calculate the size of an Es_message_t.
 *
 * @warning This function MUST NOT be used in conjunction with attempting to copy an Es_message_t (e.g.
 * by using the reported size in order to `malloc(3)` a buffer, and `memcpy(3)` an existing Es_message_t
 * into that buffer). Doing so will result in use-after-free bugs.
 *
 * @deprecated Please use `es_retain_message` to retain an Es_message_t.
 *
 * @param msg The message for which the size will be calculated
 * @return Size of the message
 */
func Es_message_size(msg *Es_message_t) uintptr {
	return unsafe.Sizeof(*msg)
}

/**
 * Retains an Es_message_t, returning a non-const pointer to the given Es_message_t for compatibility with
 * existing code.
 *
 * @warning It is invalid to attempt to write to the returned Es_message_t, despite being non-const, and
 * doing so will result in a crash.
 *
 * @deprecated Use Es_retain_message to retain a message.
 *
 * @param msg The message to be retained
 * @return non-const pointer to the retained Es_message_t.
 *
 * @brief The caller must release the memory with `es_free_message`
 */
func Es_copy_message(msg *Es_message_t) *Es_message_t {
	return msg
}

/**
 * Releases the memory associated with the given Es_message_t that was retained via `es_copy_message`
 *
 * @deprecated Use `es_release_message` to release a message.
 *
 * @param msg The message to be released
 */
func Es_free_message(msg *Es_message_t) {
	// free message
}

/**
 * Retains the given Es_message_t, extending its lifetime until released with `es_release_message`.
 *
 * @param msg The message to be retained
 *
 * @note It is necessary to retain a message when the Es_message_t provided in the event handler block of
 * `es_new_client` will be processed asynchronously.
 */
func Es_retain_message(msg *Es_message_t) {
	// retain message
}

/**
 * Releases the given Es_message_t that was previously retained with `es_retain_message`
 *
 * @param msg The message to be released
 */
func Es_release_message(msg *Es_message_t) {
	// release message
}

/**
 * Get the number of arguments in a message containing an Es_event_exec_t
 * @param event The Es_event_exec_t being inspected
 * @return The number of arguments
 */
func Es_exec_arg_count(event *Es_event_exec_t) uint32 {
	return 0
}

/**
 * Get the number of environment variables in a message containing an Es_event_exec_t
 * @param event The Es_event_exec_t being inspected
 * @return The number of environment variables
 */
func Es_exec_env_count(event *Es_event_exec_t) uint32 {
	return 0
}

/**
 * Get the number of file descriptors in a message containing an Es_event_exec_t
 * @param event The Es_event_exec_t being inspected
 * @return The number of file descriptors
 */
func Es_exec_fd_count(event *Es_event_exec_t) uint32 {
	return 0
}

/**
 * Get the argument at the specified position in the message containing an Es_event_exec_t
 * @param event The Es_event_exec_t being inspected
 * @param index Index of the argument to retrieve (starts from 0)
 * @return  Es_string_token_t containing a pointer to the argument and its length.
 *          This is a zero-allocation operation. The returned pointer must not outlive exec_event.
 * @brief Reading an an argument where `index` >= `es_exec_arg_count()` is undefined
 */
func Es_exec_arg(event *Es_event_exec_t, index uint32) Es_string_token_t {
	return Es_string_token_t{}
}

/**
 * Get the environment variable at the specified position in the message containing an Es_event_exec_t
 * @param event The Es_event_exec_t being inspected
 * @param index Index of the environment variable to retrieve (starts from 0)
 * @return  Es_string_token_t containing a pointer to the environment variable and its length.
 *          This is zero-allocation operation. The returned pointer must not outlive exec_event.
 * @brief Reading an an env where `index` >= `es_exec_env_count()` is undefined
 */
func Es_exec_env(event *Es_event_exec_t, index uint32) Es_string_token_t {
	return Es_string_token_t{}
}

/**
 * Get the file descriptor at the specified position in the message containing an Es_event_exec_t
 * @param event The Es_event_exec_t being inspected
 * @param index Index of the file descriptor to retrieve (starts from 0)
 * @return Pointer to Es_fd_t describing the file descriptor.
 *         This is zero-allocation operation. The returned pointer must not outlive exec_event.
 * @note Reading an fd where `index` >= `es_exec_fd_count()` is undefined
 */
func Es_exec_fd(event *Es_event_exec_t, index uint32) *Es_fd_t {
	return &es_fd_t{}
}

// TODO typedef struct statfs Es_statfs_t;
