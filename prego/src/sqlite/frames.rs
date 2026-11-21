//! Frames and hashes of a SQLite snapshot (ADR-0059 items 8 and 10, and the wire decisions).
//!
//! - The file is split into frames of 64 MiB; the last frame is shorter.
//! - The hash of a frame is the `sha256` of the uncompressed frame.
//! - The snapshot hash is the `sha256` of one text line for each frame, in frame order:
//!   `sha256:<64 lowercase hex>\n`. It is written `sha256:<hex>`.
//! - The file hash is the `sha256` of the whole file, written as 64 lowercase hex characters.
//! - Each frame is sent as one gzip member. The frames sent in order are a valid `.gz` of the file.

use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

/// The size of a frame, uncompressed: 64 MiB.
pub const FRAME: u64 = 64 << 20;
/// The largest compressed frame that Prego takes: 95 MiB.
pub const MAX_COMPRESSED_FRAME: u64 = 95 << 20;

/// The hashes of a file, as a save computes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    /// One `sha256:<hex>` for each frame, in order.
    pub frames: Vec<String>,
    /// `sha256:<hex>` over the frame lines.
    pub snapshot: String,
    /// The `sha256` of the whole file, 64 lowercase hex characters.
    pub file: String,
    /// The length of the file in bytes.
    pub size: u64,
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// The snapshot hash of a list of frame hashes (each `sha256:<hex>`).
pub fn snapshot_hash(frames: &[String]) -> String {
    let mut h = Sha256::new();
    for f in frames {
        h.update(f.as_bytes());
        h.update(b"\n");
    }
    format!("sha256:{}", hex(&h.finalize()))
}

/// A writer that hashes what it gets as frames of [`FRAME`] bytes and as one file, and passes the bytes on.
pub struct FrameHasher<W: Write> {
    inner: W,
    frame: Sha256,
    in_frame: u64,
    file: Sha256,
    frames: Vec<String>,
    size: u64,
}

impl<W: Write> FrameHasher<W> {
    pub fn new(inner: W) -> FrameHasher<W> {
        FrameHasher {
            inner,
            frame: Sha256::new(),
            in_frame: 0,
            file: Sha256::new(),
            frames: Vec::new(),
            size: 0,
        }
    }

    /// Closes the last frame and gives the hashes and the inner writer.
    pub fn finish(mut self) -> (Hashes, W) {
        if self.in_frame > 0 {
            let d = std::mem::take(&mut self.frame).finalize();
            self.frames.push(format!("sha256:{}", hex(&d)));
        }
        let hashes = Hashes {
            snapshot: snapshot_hash(&self.frames),
            frames: self.frames,
            file: hex(&self.file.finalize()),
            size: self.size,
        };
        (hashes, self.inner)
    }
}

impl<W: Write> Write for FrameHasher<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // At most to the end of the frame, so that each frame hash covers exactly its bytes.
        let room = (FRAME - self.in_frame) as usize;
        let n = self.inner.write(&buf[..buf.len().min(room)])?;
        self.frame.update(&buf[..n]);
        self.file.update(&buf[..n]);
        self.in_frame += n as u64;
        self.size += n as u64;
        if self.in_frame == FRAME {
            let d = std::mem::take(&mut self.frame).finalize();
            self.frames.push(format!("sha256:{}", hex(&d)));
            self.in_frame = 0;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Hashes everything that `r` gives.
pub fn hash_reader(r: &mut dyn Read) -> io::Result<Hashes> {
    let mut h = FrameHasher::new(io::sink());
    io::copy(r, &mut h)?;
    Ok(h.finish().0)
}

/// Reads the next frame (at most [`FRAME`] bytes) from `r` and gives it as one gzip member, with its hash
/// (`sha256:<hex>`) and its uncompressed length.
pub fn read_frame(r: &mut dyn Read) -> io::Result<(Vec<u8>, String, u64)> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut h = FrameHasher::new(&mut gz);
    let n = io::copy(&mut r.take(FRAME), &mut h)?;
    let (hashes, _) = h.finish();
    let body = gz.finish()?;
    let hash = hashes.frames.into_iter().next().unwrap_or_default();
    Ok((body, hash, n))
}

/// The number of frames of a file of `size` bytes.
#[cfg(test)]
pub fn frame_count(size: u64) -> u64 {
    size.div_ceil(FRAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    #[test]
    fn one_frame() {
        let data = b"SQLite format 3\0 and some pages".to_vec();
        let h = hash_reader(&mut &data[..]).unwrap();
        let f = format!("sha256:{}", sha(&data));
        assert_eq!(h.frames, vec![f.clone()]);
        assert_eq!(h.file, sha(&data));
        assert_eq!(h.size, data.len() as u64);
        // The snapshot hash is the sha256 of the line `sha256:<hex>\n`, not of the raw digest.
        assert_eq!(
            h.snapshot,
            format!("sha256:{}", sha(format!("{f}\n").as_bytes()))
        );
        assert_ne!(h.snapshot, f);
    }

    #[test]
    fn frames_split_at_64_mib() {
        let size = FRAME as usize * 2 + 4096;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        // Small writes that cross the frame ends.
        let mut h = FrameHasher::new(io::sink());
        for c in data.chunks(1_000_003) {
            h.write_all(c).unwrap();
        }
        let (got, _) = h.finish();
        let want: Vec<String> = data
            .chunks(FRAME as usize)
            .map(|c| format!("sha256:{}", sha(c)))
            .collect();
        assert_eq!(got.frames, want);
        assert_eq!(got.frames.len(), 3);
        assert_eq!(got.file, sha(&data));
        let lines: String = want.iter().map(|f| format!("{f}\n")).collect();
        assert_eq!(got.snapshot, format!("sha256:{}", sha(lines.as_bytes())));
        assert_eq!(frame_count(size as u64), 3);
        assert_eq!(frame_count(FRAME), 1);
        assert_eq!(frame_count(FRAME + 1), 2);

        // A frame read as gzip: the hash matches, and the members in order are a .gz of the file.
        let mut r = &data[..];
        let mut all = Vec::new();
        for want_hash in &want {
            let (gz, hash, _) = read_frame(&mut r).unwrap();
            assert_eq!(&hash, want_hash);
            all.extend_from_slice(&gz);
        }
        let mut back = Vec::new();
        flate2::read::MultiGzDecoder::new(&all[..])
            .read_to_end(&mut back)
            .unwrap();
        assert!(back == data);
    }

    /// The shared vectors of Prego-registry (`tests/vectors/sqlite/cases.json`): the hash rule, and the frame,
    /// snapshot and file hashes of each file.
    #[test]
    fn shared_vectors() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/sqlite");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("cases.json")).unwrap())
                .unwrap();
        assert_eq!(v["frame_bytes"].as_u64(), Some(FRAME));
        let strings = |a: &serde_json::Value| -> Vec<String> {
            a.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        let rules = v["hash_rule_cases"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        for c in rules {
            assert_eq!(
                snapshot_hash(&strings(&c["frame_hashes"])),
                c["snapshot_hash"].as_str().unwrap()
            );
        }
        let files = v["files"].as_array().unwrap();
        assert!(files.len() >= 17);
        for f in files {
            let name = f["file"].as_str().unwrap();
            let data = std::fs::read(dir.join(name)).unwrap();
            let h = hash_reader(&mut &data[..]).unwrap();
            assert_eq!(h.size, f["file_bytes"].as_u64().unwrap(), "{name}");
            assert_eq!(h.file, f["file_sha256"].as_str().unwrap(), "{name}");
            if f["expect"] == "accept" {
                assert_eq!(h.frames, strings(&f["frame_hashes"]), "{name}");
                assert_eq!(h.snapshot, f["snapshot_hash"].as_str().unwrap(), "{name}");
            }
        }
    }

    #[test]
    fn exactly_one_frame_has_no_empty_second_frame() {
        let data = vec![7u8; FRAME as usize];
        let h = hash_reader(&mut &data[..]).unwrap();
        assert_eq!(h.frames.len(), 1);
    }
}
