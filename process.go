// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
)

// Process represents common properties of an instance of a computer program as
// executed on an operating system. A Process object MUST contain at least one
// property (other than type) from this object (or one of its extensions).
type Process struct {
	STIXCyberObservableObject
	// IsHidden specifies whether the process is hidden.
	IsHidden bool `json:"is_hidden,omitempty"`
	// PID specifies the Process ID, or PID, of the process.
	PID int64 `json:"pid,omitempty"`
	// CreatedTime specifies the date/time at which the process was created.
	CreatedTime *Timestamp `json:"created_time,omitempty"`
	// Cwd specifies the current working directory of the process.
	Cwd string `json:"cwd,omitempty"`
	// CommandLine specifies the full command line used in executing the
	// process, including the process name (which may be specified individually
	// via the image_ref.name property) and any arguments.
	CommandLine string `json:"command_line,omitempty"`
	// EnvVars sSpecifies the list of environment variables associated with the
	// process as a dictionary.
	EnvVars map[string]string `json:"environment_variables,omitempty"`
	// OpenedConnections specifies the list of network connections opened by
	// the process, as a reference to one or more Network Traffic objects.
	OpenedConnections []Identifier `json:"opened_connection_refs,omitempty"`
	// CreatorUser specifies the user that created the process, as a reference
	// to a User Account object.
	CreatorUser Identifier `json:"creator_user_ref,omitempty"`
	// Image specifies the executable binary that was executed as the process
	// image, as a reference to a File object.
	Image Identifier `json:"image_ref,omitempty"`
	// Parent specifies the other process that spawned (i.e. is the parent of)
	// this one, as a reference to a Process object.
	Parent Identifier `json:"parent_ref,omitempty"`
	// Child specifies the other processes that were spawned by (i.e. children
	// of) this process, as a reference to one or more other Process objects.
	Child []Identifier `json:"child_refs,omitempty"`
}

func (o *Process) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// WindowsProcessExtension returns the Windows process extension for the object
// or nil.
func (n *Process) WindowsProcessExtension() *WindowsProcessExtension {
	data, ok := n.Extensions[ExtWindowsProcess]
	if !ok {
		return nil
	}
	return data.(*WindowsProcessExtension)
}

// WindowsServiceExtension returns the Windows service extension for the object
// or nil.
func (n *Process) WindowsServiceExtension() *WindowsServiceExtension {
	data, ok := n.Extensions[ExtWindowsService]
	if !ok {
		return nil
	}
	return data.(*WindowsServiceExtension)
}

// NewProcess creates a new Process object.
func NewProcess(opts ...STIXOption) (*Process, error) {
	if len(opts) < 1 {
		return nil, ErrPropertyMissing
	}
	id := NewIdentifier(TypeProcess)
	base := newSTIXCyberObservableObject(TypeProcess)
	base.ID = id
	obj := &Process{
		STIXCyberObservableObject: base,
	}
	err := applyOptions(obj, opts)
	return obj, err
}

// WindowsProcessExtension specifies a default extension for capturing properties
// specific to Windows processes.
type WindowsProcessExtension struct {
	// ASLR specifies whether Address Space Layout Randomization (ASLR) is
	// enabled for the process.
	ASLR bool `json:"aslr_enabled,omitempty"`
	// DEP specifies whether Data Execution Prevention (DEP) is enabled for the
	// process.
	DEP bool `json:"dep_enabled,omitempty"`
	// Priority specifies the current priority class of the process in Windows.
	// This value SHOULD be a string that ends in _CLASS.
	Priority string `json:"priority,omitempty"`
	// OwnerSID specifies the Security ID (SID) value of the owner of the
	// process.
	OwnerSID string `json:"owner_sid,omitempty"`
	// WindowTitle specifies the title of the main window of the process.
	WindowTitle string `json:"window_title,omitempty"`
	// StartupInfo specifies the STARTUP_INFO struct used by the process, as a
	// dictionary. Each name/value pair in the struct MUST be represented as a
	// key/value pair in the dictionary, where each key MUST be a
	// case-preserved version of the original name. For example, given a name
	// of "lpDesktop" the corresponding key would be lpDesktop.
	StartupInfo map[string]interface{} `json:"startup_info,omitempty"`
	// IntegrityLevel specifies the Windows integrity level, or trustworthiness,
	// of the process.
	IntegrityLevel WindowsIntegrityLevel `json:"integrity_level,omitempty"`
}

// WindowsIntegrityLevel is a security feature and represent the
// trustworthiness of an object.
type WindowsIntegrityLevel byte

// String returns the string representation of the type.
func (s WindowsIntegrityLevel) String() string {
	return windowsIntegrityLevelmap[s]
}

// MarshalJSON serializes the value to JSON.
func (s WindowsIntegrityLevel) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON deserializes the type from the json data.
func (s *WindowsIntegrityLevel) UnmarshalJSON(b []byte) error {
	if len(b) < 3 {
		*s = IntegrityLevelUnknown
		return nil
	}
	t := string(b[1 : len(b)-1])
	for k, v := range windowsIntegrityLevelmap {
		if v == t {
			*s = k
			return nil
		}
	}
	*s = IntegrityLevelUnknown
	return nil
}

const (
	// IntegrityLevelUnknown is an unknown integrity value
	IntegrityLevelUnknown WindowsIntegrityLevel = iota
	// IntegrityLevelLow represents a low level of integrity.
	IntegrityLevelLow
	// IntegrityLevelMedium represents a medium level of integrity.
	IntegrityLevelMedium
	// IntegrityLevelHigh represents a high level of integrity.
	IntegrityLevelHigh
	// IntegrityLevelSystem represents a system level of integrity.
	IntegrityLevelSystem
)

var windowsIntegrityLevelmap = map[WindowsIntegrityLevel]string{
	IntegrityLevelUnknown: "",
	IntegrityLevelLow:     "low",
	IntegrityLevelMedium:  "medium",
	IntegrityLevelHigh:    "high",
	IntegrityLevelSystem:  "system",
}

// WindowsServiceExtension specifies a default extension for capturing
// properties specific to Windows services.
type WindowsServiceExtension struct {
	// Name specifies the name of the service.
	Name string `json:"service_name,omitempty"`
	// Descriptions specifies the descriptions defined for the service.
	Descriptions []string `json:"descriptions,omitempty"`
	// DisplayName specifies the display name of the service in Windows GUI
	// controls.
	DisplayName string `json:"display_name,omitempty"`
	// GroupName specifies the name of the load ordering group of which the
	// service is a member.
	GroupName string `json:"group_name,omitempty"`
	// StartType specifies the start options defined for the service.
	StartType WindowsServiceStartType `json:"start_type,omitempty"`
	// ServiceDLL specifies the DLLs loaded by the service, as a reference to
	// one or more File objects.
	ServiceDLL []Identifier `json:"service_dll_refs,omitempty"`
	// ServiceType specifies the type of the service.
	ServiceType WindowsServiceType `json:"service_type,omitempty"`
	// ServiceStatus specifies the current status of the service.
	ServiceStatus WindowsServiceStatusType `json:"service_status,omitempty"`
}

// WindowsServiceStartType is a Windows service start type.
type WindowsServiceStartType byte

// String returns the string representation of the type.
func (s WindowsServiceStartType) String() string {
	return windowsServiceStartMap[s]
}

// MarshalJSON serializes the value to JSON.
func (s WindowsServiceStartType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON deserializes the type from the json data.
func (s *WindowsServiceStartType) UnmarshalJSON(b []byte) error {
	if len(b) < 3 {
		*s = ServiceStartUnknown
		return nil
	}
	t := string(b[1 : len(b)-1])
	for k, v := range windowsServiceStartMap {
		if v == t {
			*s = k
			return nil
		}
	}
	*s = ServiceStartUnknown
	return nil
}

const (
	// ServiceStartUnknown is an unknown service start value.
	ServiceStartUnknown WindowsServiceStartType = iota
	// ServiceStartAuto is a service started automatically by the service
	// control manager during system startup.
	ServiceStartAuto
	// ServiceStartBoot is a device driver started by the system loader. This
	// value is valid only for driver services.
	ServiceStartBoot
	// ServiceStartDemand is a service started by the service control manager
	// when a process calls the StartService function.
	ServiceStartDemand
	// ServiceStartDisabled is a service that cannot be started. Attempts to
	// start the service result in the error code ERROR_SERVICE_DISABLED.
	ServiceStartDisabled
	// ServiceStartSystem is a device driver started by the IoInitSystem
	// function. This value is valid only for driver services.
	ServiceStartSystem
)

var windowsServiceStartMap = map[WindowsServiceStartType]string{
	ServiceStartUnknown:  "",
	ServiceStartAuto:     "SERVICE_AUTO_START",
	ServiceStartBoot:     "SERVICE_BOOT_START",
	ServiceStartDemand:   "SERVICE_DEMAND_START",
	ServiceStartDisabled: "SERVICE_DISABLED",
	ServiceStartSystem:   "SERVICE_SYSTEM_ALERT",
}

// WindowsServiceType is a Windows service type.
type WindowsServiceType byte

// String returns the string representation of the type.
func (s WindowsServiceType) String() string {
	return windowsServiceMap[s]
}

// MarshalJSON serializes the value to JSON.
func (s WindowsServiceType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON deserializes the type from the json data.
func (s *WindowsServiceType) UnmarshalJSON(b []byte) error {
	if len(b) < 3 {
		*s = ServiceUnknown
		return nil
	}
	t := string(b[1 : len(b)-1])
	for k, v := range windowsServiceMap {
		if v == t {
			*s = k
			return nil
		}
	}
	*s = ServiceUnknown
	return nil
}

const (
	// ServiceUnknown is an unknown service value.
	ServiceUnknown WindowsServiceType = iota
	// ServiceKernelDriver is a device driver.
	ServiceKernelDriver
	// ServiceFileSystemDriver is a file system driver.
	ServiceFileSystemDriver
	// ServiceWin32OwnProcess runs in its own process.
	ServiceWin32OwnProcess
	// ServiceWin32ShareProcess shares a process with other services.
	ServiceWin32ShareProcess
)

var windowsServiceMap = map[WindowsServiceType]string{
	ServiceUnknown:           "",
	ServiceKernelDriver:      "SERVICE_KERNEL_DRIVER",
	ServiceFileSystemDriver:  "SERVICE_FILE_SYSTEM_DRIVER",
	ServiceWin32OwnProcess:   "SERVICE_WIN32_OWN_PROCESS",
	ServiceWin32ShareProcess: "SERVICE_WIN32_SHARE_PROCESS",
}

// WindowsServiceStatusType is a Windows service status type.
type WindowsServiceStatusType byte

// String returns the string representation of the type.
func (s WindowsServiceStatusType) String() string {
	return windowsServiceStatusMap[s]
}

// MarshalJSON serializes the value to JSON.
func (s WindowsServiceStatusType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON deserializes the type from the json data.
func (s *WindowsServiceStatusType) UnmarshalJSON(b []byte) error {
	if len(b) < 3 {
		*s = ServiceStatusUnknown
		return nil
	}
	t := string(b[1 : len(b)-1])
	for k, v := range windowsServiceStatusMap {
		if v == t {
			*s = k
			return nil
		}
	}
	*s = ServiceStatusUnknown
	return nil
}

const (
	// ServiceStatusUnknown is an unknown service status value.
	ServiceStatusUnknown WindowsServiceStatusType = iota
	// ServiceStatusContinuePending represents service continue is pending.
	ServiceStatusContinuePending
	// ServiceStatusPausePending represents service pause is pending.
	ServiceStatusPausePending
	// ServiceStatusPaused represents service is paused.
	ServiceStatusPaused
	// ServiceStatusRunning represents service is running.
	ServiceStatusRunning
	// ServiceStatusStartPending represents service is starting.
	ServiceStatusStartPending
	// ServiceStatusStopPending represents service is stopping.
	ServiceStatusStopPending
	// ServiceStatusStopped represents service is not running.
	ServiceStatusStopped
)

var windowsServiceStatusMap = map[WindowsServiceStatusType]string{
	ServiceStatusUnknown:         "",
	ServiceStatusContinuePending: "SERVICE_CONTINUE_PENDING",
	ServiceStatusPausePending:    "SERVICE_PAUSE_PENDING",
	ServiceStatusPaused:          "SERVICE_PAUSED",
	ServiceStatusRunning:         "SERVICE_RUNNING",
	ServiceStatusStartPending:    "SERVICE_START_PENDING",
	ServiceStatusStopPending:     "SERVICE_STOP_PENDING",
	ServiceStatusStopped:         "SERVICE_STOPPED",
}
