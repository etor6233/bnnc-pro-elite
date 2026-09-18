use crate::Result;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

const MAX_WINDOWS_DIRECTORY_UTF16: usize = 32_768;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Debug)]
pub struct TrustedWindowsTimeProbe {
    executable: PathBuf,
    executable_sha256: String,
}

impl TrustedWindowsTimeProbe {
    pub fn resolve() -> Result<Self> {
        let windows_directory = system_windows_directory()?;
        validate_directory(&windows_directory, "system Windows directory")?;
        let system32 = windows_directory.join("System32");
        validate_directory(&system32, "system Windows System32 directory")?;
        let executable = system32.join("w32tm.exe");
        validate_regular_non_reparse_file(&executable, "trusted w32tm executable")?;

        let canonical_system32 = fs::canonicalize(&system32)
            .map_err(|error| format!("canonicalize {}: {error}", system32.display()))?;
        let canonical_executable = fs::canonicalize(&executable)
            .map_err(|error| format!("canonicalize {}: {error}", executable.display()))?;
        if canonical_executable.parent() != Some(canonical_system32.as_path())
            || canonical_executable
                .file_name()
                .is_none_or(|name| !name.eq_ignore_ascii_case("w32tm.exe"))
        {
            return Err(format!(
                "trusted w32tm executable escaped System32: {}",
                canonical_executable.display()
            ));
        }
        let executable_sha256 = sha256_file(&canonical_executable)?;
        Ok(Self {
            executable: canonical_executable,
            executable_sha256,
        })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    pub fn query_status(&self) -> Result<Output> {
        self.status_command()?
            .output()
            .map_err(|error| format!("execute {}: {error}", self.executable.display()))
    }

    fn status_command(&self) -> Result<Command> {
        validate_regular_non_reparse_file(&self.executable, "trusted w32tm executable")?;
        let current_sha256 = sha256_file(&self.executable)?;
        if current_sha256 != self.executable_sha256 {
            return Err(format!(
                "trusted w32tm executable identity drift: expected {}, observed {}",
                self.executable_sha256, current_sha256
            ));
        }
        let mut command = Command::new(&self.executable);
        command.args(["/query", "/status"]);
        Ok(command)
    }
}

fn system_windows_directory() -> Result<PathBuf> {
    let mut buffer = vec![0_u16; MAX_WINDOWS_DIRECTORY_UTF16];
    // SAFETY: `buffer` is writable for exactly the capacity passed to the Win32 API.
    let length = unsafe {
        GetSystemWindowsDirectoryW(
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| "Windows directory buffer overflow")?,
        )
    };
    if length == 0 {
        return Err(format!(
            "GetSystemWindowsDirectoryW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let length = usize::try_from(length).map_err(|_| "Windows directory length overflow")?;
    if length >= buffer.len() {
        return Err("GetSystemWindowsDirectoryW returned an oversized path".to_owned());
    }
    let directory = PathBuf::from(OsString::from_wide(&buffer[..length]));
    if !directory.is_absolute() {
        return Err(format!(
            "GetSystemWindowsDirectoryW returned a non-absolute path: {}",
            directory.display()
        ));
    }
    Ok(directory)
}

fn validate_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(format!(
            "{label} is not a non-reparse directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_regular_non_reparse_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(format!(
            "{label} is not a regular non-reparse file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::TrustedWindowsTimeProbe;
    use std::env;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;

    const CHILD_MODE: &str = "BINANCE_LOB_W32TM_ISOLATED_CHILD";
    const CHILD_RESULT: &str = "BINANCE_LOB_W32TM_ISOLATED_RESULT";

    #[test]
    fn isolated_application_directory_child() {
        if env::var_os(CHILD_MODE).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        let result = env::var_os(CHILD_RESULT).expect("child result path");
        let probe = TrustedWindowsTimeProbe::resolve().expect("resolve trusted Windows time probe");
        let output = probe
            .query_status()
            .expect("query trusted Windows time probe");
        fs::write(
            result,
            format!(
                "{}\n{}\n{}\n",
                probe.executable().display(),
                probe.executable_sha256(),
                output.status.success()
            ),
        )
        .expect("write child result");
    }

    #[test]
    fn application_directory_w32tm_homonym_is_never_selected() {
        let directory = tempdir().expect("temporary application directory");
        let current_executable = env::current_exe().expect("current test executable");
        let child_executable = directory.path().join("segmented_capture.exe");
        fs::copy(&current_executable, &child_executable).expect("copy isolated test executable");

        let trusted =
            TrustedWindowsTimeProbe::resolve().expect("resolve trusted Windows time probe");
        let fake = directory.path().join("w32tm.exe");
        let system_where = trusted
            .executable()
            .parent()
            .expect("trusted System32 parent")
            .join("where.exe");
        fs::copy(system_where, &fake).expect("install executable homonym beside child");
        let result_path = directory.path().join("probe-result.txt");

        let command = trusted
            .status_command()
            .expect("construct trusted absolute status command");
        assert!(trusted.executable().is_absolute());
        assert_eq!(command.get_program(), trusted.executable().as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("/query"),
                std::ffi::OsStr::new("/status")
            ]
        );

        let status = Command::new(&child_executable)
            .args([
                "--exact",
                "windows_time::tests::isolated_application_directory_child",
                "--nocapture",
            ])
            .current_dir(directory.path())
            .env(CHILD_MODE, "1")
            .env(CHILD_RESULT, &result_path)
            .status()
            .expect("run isolated child");
        assert!(status.success(), "isolated child failed");
        let result = fs::read_to_string(&result_path).expect("read isolated child result");
        let mut lines = result.lines();
        let selected = lines.next().expect("selected executable path");
        let digest = lines.next().expect("selected executable digest");
        let command_succeeded = lines.next().expect("query status");
        assert_ne!(
            selected.to_ascii_lowercase(),
            fake.display().to_string().to_ascii_lowercase()
        );
        assert!(
            selected
                .to_ascii_lowercase()
                .ends_with("\\system32\\w32tm.exe")
        );
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(command_succeeded, "true");
        assert!(lines.next().is_none());
    }
}
