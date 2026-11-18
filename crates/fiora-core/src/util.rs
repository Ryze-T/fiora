//! 跨模块支撑（单点实现，避免散落重复）。

/// ISO-8601 UTC 时间戳（零依赖实现）。
pub fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let z = days as i64 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 词边界包含匹配：ASCII 词（如 "rce"）不误配 "source"/"resource"；
/// 中文短语天然有边界。所有定性关键词匹配统一走这里。
pub fn contains_word(hay: &str, word: &str) -> bool {
    let h = hay.to_lowercase();
    let w = word.to_lowercase();
    for (i, _) in h.match_indices(&w) {
        let before = h[..i].chars().next_back();
        let after = h[i + w.len()..].chars().next();
        let boundary = |c: Option<char>| c.map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true);
        if boundary(before) && boundary(after) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn word_boundary_no_source_false_positive() {
        assert!(super::contains_word("RCE via pickle", "rce"));
        assert!(super::contains_word("可导致 RCE：", "rce"));
        assert!(
            !super::contains_word("source_url 无校验", "rce"),
            "source 不算 RCE"
        );
        assert!(!super::contains_word("resource leak", "rce"));
        assert!(super::contains_word("任意代码执行", "代码执行"));
    }
}
