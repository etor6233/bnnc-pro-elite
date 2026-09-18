use crate::Result;
use serde::Serialize;
use std::ffi::c_void;
use std::mem::{MaybeUninit, size_of};
use std::net::TcpStream;
use std::os::windows::io::AsRawSocket;
use std::ptr::null_mut;
use windows_sys::Win32::Networking::WinSock::{
    SIO_TCP_INFO, TCP_INFO_v0, TCPSTATE, TCPSTATE_CLOSE_WAIT, TCPSTATE_CLOSED, TCPSTATE_CLOSING,
    TCPSTATE_ESTABLISHED, TCPSTATE_FIN_WAIT_1, TCPSTATE_FIN_WAIT_2, TCPSTATE_LAST_ACK,
    TCPSTATE_LISTEN, TCPSTATE_SYN_RCVD, TCPSTATE_SYN_SENT, TCPSTATE_TIME_WAIT, WSAGetLastError,
    WSAIoctl,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsTcpInfoV0 {
    pub schema: &'static str,
    pub api: &'static str,
    pub api_version: u32,
    pub state: i32,
    pub state_name: &'static str,
    pub mss: u32,
    pub connection_time_ms: u64,
    pub timestamps_enabled: bool,
    pub rtt_us: u32,
    pub min_rtt_us: u32,
    pub bytes_in_flight: u32,
    pub congestion_window_bytes: u32,
    pub send_window_bytes: u32,
    pub receive_window_bytes: u32,
    pub receive_buffer_bytes: u32,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub bytes_reordered: u32,
    pub bytes_retransmitted: u32,
    pub fast_retransmits: u32,
    pub duplicate_acks_in: u32,
    pub timeout_episodes: u32,
    pub syn_retransmits: u8,
}

fn state_name(state: TCPSTATE) -> &'static str {
    match state {
        TCPSTATE_CLOSED => "CLOSED",
        TCPSTATE_LISTEN => "LISTEN",
        TCPSTATE_SYN_SENT => "SYN_SENT",
        TCPSTATE_SYN_RCVD => "SYN_RECEIVED",
        TCPSTATE_ESTABLISHED => "ESTABLISHED",
        TCPSTATE_FIN_WAIT_1 => "FIN_WAIT_1",
        TCPSTATE_FIN_WAIT_2 => "FIN_WAIT_2",
        TCPSTATE_CLOSE_WAIT => "CLOSE_WAIT",
        TCPSTATE_CLOSING => "CLOSING",
        TCPSTATE_LAST_ACK => "LAST_ACK",
        TCPSTATE_TIME_WAIT => "TIME_WAIT",
        _ => "UNKNOWN",
    }
}

pub fn sample_tcp_info_v0(stream: &TcpStream) -> Result<WindowsTcpInfoV0> {
    let version = 0_u32;
    let socket = usize::try_from(stream.as_raw_socket())
        .map_err(|_| "raw Windows socket does not fit SOCKET".to_owned())?;
    let mut output = MaybeUninit::<TCP_INFO_v0>::zeroed();
    let mut returned = 0_u32;
    let output_bytes = u32::try_from(size_of::<TCP_INFO_v0>())
        .map_err(|_| "TCP_INFO_v0 size does not fit a WinSock buffer length".to_owned())?;
    // SAFETY: the socket is borrowed for the entire synchronous call; both
    // buffers have the exact lengths supplied to WinSock; no OVERLAPPED or
    // completion callback is used; output is read only after a successful call
    // returned the complete TCP_INFO_v0 structure.
    let status = unsafe {
        WSAIoctl(
            socket,
            SIO_TCP_INFO,
            (&version as *const u32).cast::<c_void>(),
            size_of::<u32>() as u32,
            output.as_mut_ptr().cast::<c_void>(),
            output_bytes,
            &mut returned,
            null_mut(),
            None,
        )
    };
    if status != 0 {
        // SAFETY: WSAGetLastError has no preconditions and is called on the same
        // thread immediately after the failed WinSock operation.
        let native = unsafe { WSAGetLastError() };
        return Err(format!("SIO_TCP_INFO v0 failed with WSA error {native}"));
    }
    if returned != output_bytes {
        return Err(format!(
            "SIO_TCP_INFO v0 returned {returned} bytes; expected {output_bytes}"
        ));
    }
    // SAFETY: success plus the exact returned size proves full initialization.
    let info = unsafe { output.assume_init() };
    Ok(WindowsTcpInfoV0 {
        schema: "WindowsTcpInfoV0",
        api: "SIO_TCP_INFO",
        api_version: version,
        state: info.State,
        state_name: state_name(info.State),
        mss: info.Mss,
        connection_time_ms: info.ConnectionTimeMs,
        timestamps_enabled: info.TimestampsEnabled,
        rtt_us: info.RttUs,
        min_rtt_us: info.MinRttUs,
        bytes_in_flight: info.BytesInFlight,
        congestion_window_bytes: info.Cwnd,
        send_window_bytes: info.SndWnd,
        receive_window_bytes: info.RcvWnd,
        receive_buffer_bytes: info.RcvBuf,
        bytes_out: info.BytesOut,
        bytes_in: info.BytesIn,
        bytes_reordered: info.BytesReordered,
        bytes_retransmitted: info.BytesRetrans,
        fast_retransmits: info.FastRetrans,
        duplicate_acks_in: info.DupAcksIn,
        timeout_episodes: info.TimeoutEpisodes,
        syn_retransmits: info.SynRetrans,
    })
}

#[cfg(test)]
mod tests {
    use super::sample_tcp_info_v0;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn samples_the_exact_connected_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accept = thread::spawn(move || listener.accept().unwrap().0);
        let client = TcpStream::connect(address).unwrap();
        let server = accept.join().unwrap();
        let client_info = sample_tcp_info_v0(&client).unwrap();
        let server_info = sample_tcp_info_v0(&server).unwrap();
        assert_eq!(client_info.schema, "WindowsTcpInfoV0");
        assert_eq!(client_info.api, "SIO_TCP_INFO");
        assert_eq!(client_info.state_name, "ESTABLISHED");
        assert_eq!(server_info.state_name, "ESTABLISHED");
    }
}
