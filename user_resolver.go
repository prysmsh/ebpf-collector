package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// UserResolver maps UIDs/GIDs to usernames/group names.
// It reads /etc/passwd and /etc/group from the host filesystem,
// adjusting paths based on procRoot (e.g. /host/proc → /host/etc/passwd).
type UserResolver struct {
	mu       sync.RWMutex
	users    map[uint32]string
	groups   map[uint32]string
	procRoot string
}

// NewUserResolver creates a UserResolver and loads passwd/group files.
func NewUserResolver(procRoot string) *UserResolver {
	r := &UserResolver{
		users:    make(map[uint32]string),
		groups:   make(map[uint32]string),
		procRoot: procRoot,
	}
	r.LoadPasswd()
	r.LoadGroup()
	return r
}

// passwdPath returns the path to the passwd file based on procRoot.
// If procRoot is "/proc", we read "/etc/passwd" (same host).
// If procRoot is e.g. "/host/proc", we read "/host/etc/passwd".
func (r *UserResolver) passwdPath() string {
	if r.procRoot == "/proc" {
		return "/etc/passwd"
	}
	// Strip trailing "/proc" and append "/etc/passwd"
	base := strings.TrimSuffix(r.procRoot, "/proc")
	return base + "/etc/passwd"
}

// groupPath returns the path to the group file based on procRoot.
func (r *UserResolver) groupPath() string {
	if r.procRoot == "/proc" {
		return "/etc/group"
	}
	base := strings.TrimSuffix(r.procRoot, "/proc")
	return base + "/etc/group"
}

// LoadPasswd parses the passwd file (format: name:x:uid:gid:...).
func (r *UserResolver) LoadPasswd() {
	path := r.passwdPath()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	users := make(map[uint32]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		uid, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		users[uint32(uid)] = parts[0]
	}

	r.mu.Lock()
	r.users = users
	r.mu.Unlock()
}

// LoadGroup parses the group file (format: name:x:gid:...).
func (r *UserResolver) LoadGroup() {
	path := r.groupPath()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	groups := make(map[uint32]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		gid, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		groups[uint32(gid)] = parts[0]
	}

	r.mu.Lock()
	r.groups = groups
	r.mu.Unlock()
}

// ResolveUID returns the username for the given UID, or "uid=N" if not found.
func (r *UserResolver) ResolveUID(uid uint32) string {
	r.mu.RLock()
	name, ok := r.users[uid]
	r.mu.RUnlock()
	if ok {
		return name
	}
	return fmt.Sprintf("uid=%d", uid)
}

// ResolveGID returns the group name for the given GID, or "gid=N" if not found.
func (r *UserResolver) ResolveGID(gid uint32) string {
	r.mu.RLock()
	name, ok := r.groups[gid]
	r.mu.RUnlock()
	if ok {
		return name
	}
	return fmt.Sprintf("gid=%d", gid)
}

// Refresh reloads the passwd and group files.
func (r *UserResolver) Refresh() {
	r.LoadPasswd()
	r.LoadGroup()
}
