//! Minimal Windows ETW controller for bounded TCP lifecycle evidence.
//!
//! The unsafe boundary follows the Microsoft ETW controller lifecycle and uses
//! only generated `windows-sys` ABI definitions. It is diagnostic-only and has
//! no authority over raw market data.

use std::ffi::OsStr;
use std::mem::{align_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    EVENT_CONTROL_CODE_DISABLE_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_PROPERTIES,
    EnableTraceEx2, StartTraceW, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::core::GUID;

pub const KERNEL_NETWORK_PROVIDER: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
pub const TCP_LIFECYCLE_EVENT_IDS: [u16; 11] = [12, 13, 14, 15, 16, 17, 28, 29, 30, 31, 32];
pub const TCP_IPV4_IPV6_KEYWORDS: u64 = 0x30;
pub const MAX_EVENT_FILTER_EVENT_ID_COUNT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceStatistics {
    pub number_of_buffers: u32,
    pub free_buffers: u32,
    pub events_lost: u32,
    pub buffers_written: u32,
    pub log_buffers_lost: u32,
    pub realtime_buffers_lost: u32,
}

#[derive(Debug)]
struct PropertiesBuffer {
    words: Vec<u64>,
}

impl PropertiesBuffer {
    fn new(session_name: &[u16], etl_path: &[u16], maximum_file_mib: u32) -> Result<Self, String> {
        if session_name.last() != Some(&0) || etl_path.last() != Some(&0) {
            return Err("ETW names must be NUL-terminated".to_owned());
        }
        if !(16..=1024).contains(&maximum_file_mib) {
            return Err("ETW maximum file size must be within 16..=1024 MiB".to_owned());
        }

        let header_bytes = size_of::<EVENT_TRACE_PROPERTIES>();
        let logger_bytes = session_name
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| "ETW logger name size overflow".to_owned())?;
        let path_bytes = etl_path
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| "ETW log path size overflow".to_owned())?;
        let total_bytes = header_bytes
            .checked_add(logger_bytes)
            .and_then(|value| value.checked_add(path_bytes))
            .ok_or_else(|| "ETW properties allocation overflow".to_owned())?;
        let total_u32 = u32::try_from(total_bytes)
            .map_err(|_| "ETW properties exceed the Win32 u32 size".to_owned())?;
        let logger_offset =
            u32::try_from(header_bytes).map_err(|_| "ETW logger offset overflow".to_owned())?;
        let path_offset = u32::try_from(header_bytes + logger_bytes)
            .map_err(|_| "ETW log path offset overflow".to_owned())?;
        let word_count = total_bytes.div_ceil(size_of::<u64>());
        let mut value = Self {
            words: vec![0_u64; word_count],
        };

        // SAFETY: `Vec<u64>` provides alignment at least as strict as
        // EVENT_TRACE_PROPERTIES. The allocation is sized above for the fixed
        // header and both trailing UTF-16 strings. All writes remain within it.
        unsafe {
            let properties = &mut *value.as_mut_ptr();
            properties.Wnode.BufferSize = total_u32;
            properties.Wnode.ClientContext = 1; // Query-performance-counter timestamps.
            properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            properties.BufferSize = 64; // KiB per ETW buffer.
            properties.MinimumBuffers = 4;
            properties.MaximumBuffers = 16;
            properties.MaximumFileSize = maximum_file_mib;
            properties.LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR;
            properties.FlushTimer = 1;
            properties.LoggerNameOffset = logger_offset;
            properties.LogFileNameOffset = path_offset;

            let bytes = std::slice::from_raw_parts_mut(
                value.words.as_mut_ptr().cast::<u8>(),
                value.words.len() * size_of::<u64>(),
            );
            write_utf16(bytes, header_bytes, session_name)?;
            write_utf16(bytes, header_bytes + logger_bytes, etl_path)?;
        }
        Ok(value)
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.words.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>()
    }

    fn properties(&self) -> &EVENT_TRACE_PROPERTIES {
        // SAFETY: constructed from a zeroed, correctly aligned Vec<u64> whose
        // first bytes are always a complete EVENT_TRACE_PROPERTIES value.
        unsafe { &*self.words.as_ptr().cast::<EVENT_TRACE_PROPERTIES>() }
    }
}

fn write_utf16(bytes: &mut [u8], offset: usize, value: &[u16]) -> Result<(), String> {
    let byte_len = value
        .len()
        .checked_mul(2)
        .ok_or_else(|| "UTF-16 byte length overflow".to_owned())?;
    let end = offset
        .checked_add(byte_len)
        .ok_or_else(|| "UTF-16 destination overflow".to_owned())?;
    let destination = bytes
        .get_mut(offset..end)
        .ok_or_else(|| "UTF-16 destination is outside ETW properties".to_owned())?;
    for (index, code_unit) in value.iter().copied().enumerate() {
        let start = index * 2;
        destination[start..start + 2].copy_from_slice(&code_unit.to_ne_bytes());
    }
    Ok(())
}

fn nul_terminated(value: &OsStr, field: &str) -> Result<Vec<u16>, String> {
    let mut encoded: Vec<u16> = value.encode_wide().collect();
    if encoded.is_empty() || encoded.contains(&0) {
        return Err(format!("{field} must be non-empty and contain no NUL"));
    }
    encoded.push(0);
    Ok(encoded)
}

fn validate_session_name(value: &str) -> Result<Vec<u16>, String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("ETW session name must be 1..=128 ASCII alphanumeric, '-' or '_'".to_owned());
    }
    nul_terminated(OsStr::new(value), "ETW session name")
}

#[derive(Debug)]
struct EventIdFilter {
    words: Vec<u16>,
}

impl EventIdFilter {
    fn new(event_ids: &[u16]) -> Result<Self, String> {
        if event_ids.is_empty() || event_ids.len() > MAX_EVENT_FILTER_EVENT_ID_COUNT {
            return Err(format!(
                "ETW event-ID filter must contain 1..={MAX_EVENT_FILTER_EVENT_ID_COUNT} IDs"
            ));
        }
        if event_ids.contains(&0) {
            return Err("ETW event ID zero is not allowed".to_owned());
        }
        if event_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("ETW event IDs must be strictly increasing and unique".to_owned());
        }
        let count =
            u16::try_from(event_ids.len()).map_err(|_| "ETW event-ID count overflow".to_owned())?;
        let mut words = Vec::with_capacity(2 + event_ids.len());
        words.push(1); // FilterIn=true, Reserved=0 as two little-endian bytes.
        words.push(count);
        words.extend_from_slice(event_ids);
        Ok(Self { words })
    }

    fn descriptor(&mut self) -> Result<EVENT_FILTER_DESCRIPTOR, String> {
        let size = u32::try_from(self.words.len() * size_of::<u16>())
            .map_err(|_| "ETW event-ID descriptor size overflow".to_owned())?;
        Ok(EVENT_FILTER_DESCRIPTOR {
            Ptr: self.words.as_mut_ptr() as usize as u64,
            Size: size,
            Type: EVENT_FILTER_TYPE_EVENT_ID,
        })
    }
}

pub struct KernelNetworkTrace {
    handle: CONTROLTRACE_HANDLE,
    properties: PropertiesBuffer,
    provider_enabled: bool,
    stopped: bool,
}

impl KernelNetworkTrace {
    pub fn start(
        session_name: &str,
        etl_path: &Path,
        maximum_file_mib: u32,
    ) -> Result<Self, String> {
        if !etl_path.is_absolute() {
            return Err("ETW path must be absolute".to_owned());
        }
        if etl_path.exists() {
            return Err(format!(
                "ETW path already exists (create-only): {}",
                etl_path.display()
            ));
        }
        let parent = etl_path
            .parent()
            .ok_or_else(|| "ETW path has no parent".to_owned())?;
        if !parent.is_dir() {
            return Err(format!("ETW parent does not exist: {}", parent.display()));
        }

        let session_utf16 = validate_session_name(session_name)?;
        let path_utf16 = nul_terminated(etl_path.as_os_str(), "ETW path")?;
        let mut properties = PropertiesBuffer::new(&session_utf16, &path_utf16, maximum_file_mib)?;
        let mut handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: all pointers reference live, correctly aligned and initialized
        // buffers for the duration of the Win32 call.
        let start_error =
            unsafe { StartTraceW(&mut handle, session_utf16.as_ptr(), properties.as_mut_ptr()) };
        if start_error != 0 {
            return Err(win32_error("StartTraceW", start_error));
        }

        let mut trace = Self {
            handle,
            properties,
            provider_enabled: false,
            stopped: false,
        };
        if let Err(error) = trace.enable_provider() {
            let cleanup = trace.stop_session_only();
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => format!("{error}; cleanup also failed: {cleanup_error}"),
            });
        }
        Ok(trace)
    }

    fn enable_provider(&mut self) -> Result<(), String> {
        let mut filter = EventIdFilter::new(&TCP_LIFECYCLE_EVENT_IDS)?;
        let mut descriptor = filter.descriptor()?;
        let parameters = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableFilterDesc: &mut descriptor,
            FilterDescCount: 1,
            ..Default::default()
        };
        // SAFETY: provider GUID, parameters, descriptor and backing filter blob
        // stay alive and immutable for the entire call. ETW copies the filter.
        let error = unsafe {
            EnableTraceEx2(
                self.handle,
                &KERNEL_NETWORK_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION as u8,
                TCP_IPV4_IPV6_KEYWORDS,
                0,
                0,
                &parameters,
            )
        };
        if error != 0 {
            return Err(win32_error("EnableTraceEx2(enable)", error));
        }
        self.provider_enabled = true;
        Ok(())
    }

    pub fn query(&mut self) -> Result<TraceStatistics, String> {
        // SAFETY: the handle owns the session and the mutable properties buffer
        // has the size and offsets declared at StartTraceW.
        let error = unsafe {
            ControlTraceW(
                self.handle,
                ptr::null(),
                self.properties.as_mut_ptr(),
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if error != 0 {
            return Err(win32_error("ControlTraceW(query)", error));
        }
        Ok(self.statistics())
    }

    pub fn finish(mut self) -> Result<TraceStatistics, String> {
        let disable = self.disable_provider();
        let stop = self.stop_session_only();
        match (disable, stop) {
            (Ok(()), Ok(())) => Ok(self.statistics()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(disable_error), Err(stop_error)) => Err(format!("{disable_error}; {stop_error}")),
        }
    }

    fn disable_provider(&mut self) -> Result<(), String> {
        if !self.provider_enabled {
            return Ok(());
        }
        let parameters = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            ..Default::default()
        };
        // SAFETY: the session handle and provider GUID are valid; no filter is
        // supplied for the documented disable control code.
        let error = unsafe {
            EnableTraceEx2(
                self.handle,
                &KERNEL_NETWORK_PROVIDER,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                &parameters,
            )
        };
        if error != 0 {
            return Err(win32_error("EnableTraceEx2(disable)", error));
        }
        self.provider_enabled = false;
        Ok(())
    }

    fn stop_session_only(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        // SAFETY: the handle owns the named session and the properties buffer
        // remains valid for the final statistics update.
        let error = unsafe {
            ControlTraceW(
                self.handle,
                ptr::null(),
                self.properties.as_mut_ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if error != 0 {
            return Err(win32_error("ControlTraceW(stop)", error));
        }
        self.stopped = true;
        Ok(())
    }

    fn statistics(&self) -> TraceStatistics {
        let properties = self.properties.properties();
        TraceStatistics {
            number_of_buffers: properties.NumberOfBuffers,
            free_buffers: properties.FreeBuffers,
            events_lost: properties.EventsLost,
            buffers_written: properties.BuffersWritten,
            log_buffers_lost: properties.LogBuffersLost,
            realtime_buffers_lost: properties.RealTimeBuffersLost,
        }
    }
}

impl Drop for KernelNetworkTrace {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.disable_provider();
            let _ = self.stop_session_only();
        }
    }
}

fn win32_error(operation: &str, code: u32) -> String {
    format!(
        "{operation} failed with Win32 error {code}: {}",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

pub fn abi_contract() -> Result<(), String> {
    if align_of::<EVENT_TRACE_PROPERTIES>() > align_of::<u64>() {
        return Err("Vec<u64> does not satisfy EVENT_TRACE_PROPERTIES alignment".to_owned());
    }
    if size_of::<EVENT_FILTER_DESCRIPTOR>() != 16 {
        return Err("unexpected EVENT_FILTER_DESCRIPTOR ABI size".to_owned());
    }
    if size_of::<windows_sys::Win32::System::Diagnostics::Etw::EVENT_FILTER_EVENT_ID>() != 6 {
        return Err("unexpected EVENT_FILTER_EVENT_ID ABI size".to_owned());
    }
    EventIdFilter::new(&TCP_LIFECYCLE_EVENT_IDS)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_filter_matches_microsoft_layout() {
        let mut filter = EventIdFilter::new(&[12, 13, 17]).expect("filter");
        let descriptor = filter.descriptor().expect("descriptor");
        assert_eq!(descriptor.Type, EVENT_FILTER_TYPE_EVENT_ID);
        assert_eq!(descriptor.Size, 10);
        assert_eq!(filter.words, vec![1, 3, 12, 13, 17]);
        assert_eq!(descriptor.Ptr, filter.words.as_ptr() as usize as u64);
    }

    #[test]
    fn event_filter_rejects_ambiguous_or_oversized_inputs() {
        assert!(EventIdFilter::new(&[]).is_err());
        assert!(EventIdFilter::new(&[0]).is_err());
        assert!(EventIdFilter::new(&[13, 12]).is_err());
        assert!(EventIdFilter::new(&[12, 12]).is_err());
        assert!(EventIdFilter::new(&(1_u16..=65).collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn properties_buffer_has_exact_offsets_and_nul_termination() {
        let session = validate_session_name("BinanceEtw_test").expect("session");
        let path = nul_terminated(OsStr::new(r"C:\trace\evidence.etl"), "path").expect("path");
        let value = PropertiesBuffer::new(&session, &path, 64).expect("properties");
        let properties = value.properties();
        assert_eq!(
            properties.LoggerNameOffset as usize,
            size_of::<EVENT_TRACE_PROPERTIES>()
        );
        assert_eq!(
            properties.LogFileNameOffset as usize,
            size_of::<EVENT_TRACE_PROPERTIES>() + session.len() * 2
        );
        assert_eq!(properties.MaximumFileSize, 64);
        assert_eq!(properties.Wnode.Flags, WNODE_FLAG_TRACED_GUID);
        assert_eq!(properties.Wnode.ClientContext, 1);
        assert!(properties.Wnode.BufferSize as usize >= size_of::<EVENT_TRACE_PROPERTIES>());
    }

    #[test]
    fn public_contract_excludes_high_volume_events() {
        abi_contract().expect("ABI contract");
        for excluded in [10_u16, 11, 18, 26, 27, 34, 42, 43, 49, 58, 59] {
            assert!(!TCP_LIFECYCLE_EVENT_IDS.contains(&excluded));
        }
    }
}
