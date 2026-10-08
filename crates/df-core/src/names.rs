//! 设备显示名称与安全文件名（与第 11 / 10.3 节规则一致）。

/// 显示名称：1..64 个 UTF-16 码元，去控制字符、去首尾空白；截断不拆代理对。
/// 返回 None 表示不合规。
pub fn sanitize_display_name(raw: &str) -> Option<String> {
    let trimmed: String = raw.trim().chars().filter(|c| !c.is_control()).collect();
    let len16 = trimmed.encode_utf16().count();
    if len16 == 0 || len16 > 64 {
        return None;
    }
    Some(trimmed)
}

/// 按限制截断到 ≤64 个 UTF-16 码元，不拆代理对。
pub fn truncate_display_name(raw: &str) -> String {
    let mut out = String::new();
    let mut len16 = 0usize;
    for ch in raw.chars() {
        let l = ch.len_utf16();
        if len16 + l > 64 {
            break;
        }
        out.push(ch);
        len16 += l;
    }
    out
}

/// 默认设备名：计算机名（本 crate 只提供主机名兜底，平台层可用更合适的来源覆盖）。
pub fn default_device_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| sanitize_display_name(&h).unwrap_or_else(|| "Desktop".into()))
        .unwrap_or_else(|| "Desktop".into())
}

/// 生成安全文件名：去除平台非法字符与控制字符，避免 `.`/`..`，不覆盖已有文件时加序号。
pub fn safe_filename(name: &str) -> String {
    let mut s: String = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '/' | '\\' => '_',
            _ => c,
        })
        .collect();

    #[cfg(target_os = "windows")]
    {
        const BAD: [char; 9] = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
        s = s.chars().map(|c| if BAD.contains(&c) { '_' } else { c }).collect();
        while s.ends_with('.') || s.ends_with(' ') {
            s.pop();
        }
        const RESERVED: [&str; 22] = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
        if RESERVED.contains(&stem.as_str()) {
            s = format!("_{s}");
        }
    }

    if s.is_empty() || s == "." || s == ".." {
        s = "file".to_string();
    }
    // 协议文件名可达 128 字符，常见文件系统单个名字上限 255 字节（UTF-8）；
    // 留出 " (n)" 去重后缀的余量。超长时截短主名、保留扩展名（不能套用 64 码元的显示名称规则）。
    truncate_filename(&s, 200)
}

/// 截短到 ≤ `max_bytes` 个 UTF-8 字节：保留不超过 16 字节的扩展名，不拆字符。
fn truncate_filename(name: &str, max_bytes: usize) -> String {
    if name.len() <= max_bytes {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if dot > 0 && name.len() - dot <= 16 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    };
    let budget = max_bytes - ext.len();
    let mut cut = budget.min(stem.len());
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{ext}", &stem[..cut])
}

/// 不覆盖已有文件：存在则插入 ` (n)`。
pub fn unique_filename(dir: &std::path::Path, name: &str) -> String {
    let safe = safe_filename(name);
    let mut candidate = safe.clone();
    let stem;
    let ext;
    if let Some(dot) = safe.rfind('.') {
        stem = safe[..dot].to_string();
        ext = safe[dot..].to_string();
    } else {
        stem = safe.clone();
        ext = String::new();
    }
    let mut n = 1u32;
    while dir.join(&candidate).exists() {
        candidate = format!("{stem} ({n}){ext}");
        n += 1;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_rules() {
        assert!(sanitize_display_name("  我的电脑\u{7} ").unwrap() == "我的电脑");
        assert!(sanitize_display_name("").is_none());
        assert!(sanitize_display_name("   ").is_none());
        let long = "a".repeat(100);
        assert_eq!(truncate_display_name(&long).chars().count(), 64);
        // 代理对不拆开
        let emoji = "😀".repeat(40); // 每个占 2 个码元
        assert_eq!(truncate_display_name(&emoji).encode_utf16().count(), 64);
    }

    #[test]
    fn filename_rules() {
        assert_eq!(safe_filename("a/b\\c"), "a_b_c");
        assert_eq!(safe_filename("."), "file");
        assert_eq!(safe_filename(".."), "file");
        assert_eq!(safe_filename(""), "file");
        assert!(!safe_filename("a\u{1}b").contains('\u{1}'));
        // Lineage 发来的文件名常带 36 字符 UUID 前缀：超过 64 字符也必须原样保留扩展名
        let long = "d7db9d06-9c41-47d9-b7be-de2bca88c7b3-20260922_155558_linux_log.zip";
        assert_eq!(safe_filename(long), long);
        let huge = format!("{}.tar.gz", "名".repeat(100));
        let cut = safe_filename(&huge);
        assert!(cut.len() <= 200 && cut.ends_with(".gz"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reserved() {
        assert_eq!(safe_filename("CON.txt"), "_CON.txt");
        assert_eq!(safe_filename("a:b"), "a_b");
    }

    #[test]
    fn unique() {
        let dir = std::env::temp_dir().join("df-name-test");
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(dir.join("x.txt"));
        let _ = std::fs::remove_file(dir.join("x (1).txt"));
        assert_eq!(unique_filename(&dir, "x.txt"), "x.txt");
        std::fs::write(dir.join("x.txt"), b"1").unwrap();
        assert_eq!(unique_filename(&dir, "x.txt"), "x (1).txt");
        std::fs::write(dir.join("x (1).txt"), b"1").unwrap();
        assert_eq!(unique_filename(&dir, "x.txt"), "x (2).txt");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
