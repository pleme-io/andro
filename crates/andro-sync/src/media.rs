use chrono::NaiveDate;
use std::path::{Path, PathBuf};
use tracing::info;

/// Organizes media files by EXIF date into directory structure.
pub struct MediaOrganizer {
    output_dir: PathBuf,
}

impl MediaOrganizer {
    pub fn new(output_dir: &Path) -> Self {
        Self {
            output_dir: output_dir.to_path_buf(),
        }
    }

    /// Determine the destination path for a media file based on EXIF date.
    /// Falls back to file modification time if no EXIF data.
    /// Structure: output_dir/YYYY/MM/filename
    pub fn destination_path(&self, file_path: &Path) -> PathBuf {
        let date = self
            .exif_date(file_path)
            .or_else(|| self.mtime_date(file_path))
            .unwrap_or_else(|| NaiveDate::from_ymd_opt(2000, 1, 1).unwrap());

        let year = date.format("%Y").to_string();
        let month = date.format("%m").to_string();
        let filename = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        self.output_dir.join(year).join(month).join(filename)
    }

    /// Extract date from EXIF metadata.
    fn exif_date(&self, path: &Path) -> Option<NaiveDate> {
        let file = std::fs::File::open(path).ok()?;
        let mut reader = std::io::BufReader::new(file);
        let exif = exif::Reader::new().read_from_container(&mut reader).ok()?;

        let field = exif.get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY)?;
        let value = field.display_value().to_string();

        // Format: "2024-06-15 14:30:22" or "2024:06:15 14:30:22"
        let date_part = value.split(' ').next()?;
        let parts: Vec<&str> = date_part.split(|c| c == '-' || c == ':').collect();
        if parts.len() >= 3 {
            let year = parts[0].parse().ok()?;
            let month = parts[1].parse().ok()?;
            let day = parts[2].parse().ok()?;
            NaiveDate::from_ymd_opt(year, month, day)
        } else {
            None
        }
    }

    /// Fall back to file modification time.
    fn mtime_date(&self, path: &Path) -> Option<NaiveDate> {
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok()?;
        let datetime: chrono::DateTime<chrono::Utc> = modified.into();
        Some(datetime.date_naive())
    }

    /// Check if two files are duplicates via BLAKE3 hash.
    pub fn is_duplicate(file_a: &Path, file_b: &Path) -> bool {
        let hash_a = std::fs::read(file_a).map(|d| blake3::hash(&d));
        let hash_b = std::fs::read(file_b).map(|d| blake3::hash(&d));
        match (hash_a, hash_b) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }

    /// Organize a file: compute destination, create dirs, move/copy.
    pub fn organize_file(&self, source: &Path, copy: bool) -> std::io::Result<PathBuf> {
        let dest = self.destination_path(source);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if copy {
            std::fs::copy(source, &dest)?;
            info!(src = %source.display(), dst = %dest.display(), "copied");
        } else {
            std::fs::rename(source, &dest)?;
            info!(src = %source.display(), dst = %dest.display(), "moved");
        }

        Ok(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn destination_path_structure() {
        let org = MediaOrganizer::new(Path::new("/output"));
        let dest = org.destination_path(Path::new("/input/photo.jpg"));
        // Should produce /output/YYYY/MM/photo.jpg (year/month from mtime or fallback)
        assert!(dest.starts_with("/output"));
        assert_eq!(dest.file_name().unwrap(), "photo.jpg");
    }

    #[test]
    fn duplicate_detection_same_content() {
        let tmp = std::env::temp_dir();
        let a = tmp.join("andro_test_dup_a.txt");
        let b = tmp.join("andro_test_dup_b.txt");
        std::fs::write(&a, b"identical content").unwrap();
        std::fs::write(&b, b"identical content").unwrap();
        assert!(MediaOrganizer::is_duplicate(&a, &b));
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    #[test]
    fn duplicate_detection_different_content() {
        let tmp = std::env::temp_dir();
        let a = tmp.join("andro_test_diff_a.txt");
        let b = tmp.join("andro_test_diff_b.txt");
        std::fs::write(&a, b"content a").unwrap();
        std::fs::write(&b, b"content b").unwrap();
        assert!(!MediaOrganizer::is_duplicate(&a, &b));
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }
}
