//! Thread priority for hot-path threads (SPEC §6.1): MMCSS "Games" on
//! Windows, falling back to `THREAD_PRIORITY_TIME_CRITICAL`. No-op
//! elsewhere.

/// How the current thread was boosted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boost {
    Mmcss,
    TimeCritical,
    None,
}

/// Raises the calling thread's scheduling priority for the rest of its
/// life.
#[cfg(windows)]
pub fn boost_current_thread() -> Boost {
    use windows_sys::Win32::System::Threading::{
        AvSetMmThreadCharacteristicsW, GetCurrentThread, SetThreadPriority,
        THREAD_PRIORITY_TIME_CRITICAL,
    };

    let task: Vec<u16> = "Games".encode_utf16().chain(Some(0)).collect();
    let mut index = 0u32;
    // SAFETY: NUL-terminated task name and a valid out pointer. The MMCSS
    // registration is intentionally never reverted: it ends with the thread.
    unsafe {
        if !AvSetMmThreadCharacteristicsW(task.as_ptr(), &mut index).is_null() {
            return Boost::Mmcss;
        }
        if SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL) != 0 {
            return Boost::TimeCritical;
        }
    }
    Boost::None
}

#[cfg(not(windows))]
pub fn boost_current_thread() -> Boost {
    Boost::None
}
