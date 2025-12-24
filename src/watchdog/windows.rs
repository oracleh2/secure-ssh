//! Watchdog для Windows - отслеживание USB-накопителя

use std::path::PathBuf;
use super::UsbWatchdog;
use crate::config;

/// Реализация watchdog для Windows
pub struct WindowsWatchdog {
    /// Путь к диску (например, "E:")
    drive_path: PathBuf,
    /// Файл-маркер для проверки
    marker_file: Option<PathBuf>,
}

impl WindowsWatchdog {
    pub fn new() -> Option<Self> {
        let exe_dir = config::get_exe_dir().ok()?;

        // На Windows получаем букву диска
        let drive_path = if let Some(prefix) = exe_dir.components().next() {
            PathBuf::from(prefix.as_os_str())
        } else {
            exe_dir.clone()
        };

        // Ищем маркер-файл
        let marker = config::get_marker_path().ok();
        let marker_exists = marker.as_ref().map(|p| p.exists()).unwrap_or(false);

        Some(Self {
            drive_path,
            marker_file: if marker_exists { marker } else { None },
        })
    }

    /// Проверить, является ли диск съёмным
    #[cfg(windows)]
    #[allow(dead_code)]
    pub fn is_removable(&self) -> bool {
        use windows::Win32::Storage::FileSystem::GetDriveTypeW;

        // DRIVE_REMOVABLE = 2
        const DRIVE_REMOVABLE: u32 = 2;

        let drive_str = self.drive_path.to_string_lossy();
        if drive_str.len() >= 2 {
            let drive_root: Vec<u16> = format!("{}\\", &drive_str[..2])
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let drive_type = GetDriveTypeW(windows::core::PCWSTR(drive_root.as_ptr()));
                return drive_type == DRIVE_REMOVABLE;
            }
        }
        false
    }

    #[cfg(not(windows))]
    #[allow(dead_code)]
    pub fn is_removable(&self) -> bool {
        false
    }
}

impl UsbWatchdog for WindowsWatchdog {
    fn is_present(&self) -> bool {
        // Сначала проверяем маркер-файл
        if let Some(ref marker) = self.marker_file {
            return marker.exists();
        }

        // Иначе проверяем существование диска
        self.drive_path.exists()
    }
}
