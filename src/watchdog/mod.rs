//! USB watchdog - отслеживание извлечения USB-накопителя

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Трейт для реализаций watchdog
pub trait UsbWatchdog: Send {
    /// Проверить, присутствует ли USB-накопитель
    fn is_present(&self) -> bool;
}

/// Создать watchdog для текущей платформы
pub fn create_watchdog() -> Option<Box<dyn UsbWatchdog>> {
    #[cfg(target_os = "linux")]
    {
        linux::LinuxWatchdog::new().map(|w| Box::new(w) as Box<dyn UsbWatchdog>)
    }

    #[cfg(target_os = "macos")]
    {
        macos::MacOsWatchdog::new().map(|w| Box::new(w) as Box<dyn UsbWatchdog>)
    }

    #[cfg(target_os = "windows")]
    {
        windows::WindowsWatchdog::new().map(|w| Box::new(w) as Box<dyn UsbWatchdog>)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}
