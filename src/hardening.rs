//! Keeping real keys out of reach of other processes of the same user.
//!
//! The gateway holds real keys in memory for its whole lifetime. Its own API
//! has no read channel for them (`route ls` prints the vkey, `export` strips
//! them), but the operating system has one: any process running as the same
//! uid can read `/proc/<pid>/mem`, or attach a debugger. For an agent that is
//! the same user, that is a one-line command.

/// Linux: make this process unreadable to every process without
/// `CAP_SYS_PTRACE`, including the rest of our own uid.
///
/// `PR_SET_DUMPABLE = 0` denies `/proc/<pid>/{mem,environ,maps,fd}` and
/// `PTRACE_ATTACH` to same-uid readers — `kernel.yama.ptrace_scope` is
/// irrelevant here, and 0 on many distributions. Core dumps stop as a side
/// effect, which is what you want for a process holding keys.
///
/// This only works on the process that calls it: `execve(2)` resets the flag
/// to 1, so a launcher cannot do it on someone else's behalf — which is
/// precisely why a wrapper around the agent (`envp run` and friends) cannot
/// provide this protection, and a long-lived gateway can.
///
/// macOS (`task_for_pid`) and Windows (`SeDebugPrivilege`) already refuse
/// same-user memory reads without privilege escalation, so this is a no-op
/// there.
#[cfg(target_os = "linux")]
pub fn hide_from_same_uid() -> std::io::Result<()> {
    // SAFETY: prctl(2) with PR_SET_DUMPABLE takes a single integer argument.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn hide_from_same_uid() -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn dumpable_is_cleared() {
        hide_from_same_uid().expect("prctl(PR_SET_DUMPABLE, 0)");
        // SAFETY: PR_GET_DUMPABLE takes no extra arguments.
        let value = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(value, 0);
    }

    #[test]
    fn other_platforms_accept_the_call() {
        // The non-Linux arm is a no-op that still reports success.
        if !cfg!(target_os = "linux") {
            assert!(hide_from_same_uid().is_ok());
        }
    }
}
