use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::Context;
use buffers::{ByteBuf, ByteBufOwned};
use librqbit_core::{
    lengths::{ChunkInfo, ValidPieceIndex},
    torrent_metainfo::ValidatedTorrentMetaV1Info,
};
use peer_binary_protocol::{DoubleBufHelper, Piece};
use sha1w::{ISha1, Sha1};
use tracing::{debug, trace, warn};

use crate::{
    file_info::FileInfo,
    storage::TorrentStorage,
    type_aliases::{BF, FileInfos, PeerHandle},
};

pub fn update_hash_from_file<Sha1: ISha1>(
    file_id: usize,
    file_info: &FileInfo,
    mut pos: u64,
    files: &dyn TorrentStorage,
    hash: &mut Sha1,
    buf: &mut [u8],
    mut bytes_to_read: usize,
) -> anyhow::Result<()> {
    let mut read = 0;
    while bytes_to_read > 0 {
        let chunk = std::cmp::min(buf.len(), bytes_to_read);
        if file_info.attrs.padding {
            buf[..chunk].fill(0);
        } else {
            files
                .pread_exact(file_id, pos, &mut buf[..chunk])
                .with_context(|| {
                    format!("failed reading chunk of size {chunk}, read so far {read}")
                })?;
        }
        bytes_to_read -= chunk;
        read += chunk;
        pos += chunk as u64;
        hash.update(&buf[..chunk]);
    }
    Ok(())
}

pub(crate) struct FileOps<'a> {
    torrent: &'a ValidatedTorrentMetaV1Info<ByteBufOwned>,
    files: &'a dyn TorrentStorage,
    file_infos: &'a FileInfos,
    phantom_data: PhantomData<Sha1>,
}

impl<'a> FileOps<'a> {
    pub fn new(
        torrent: &'a ValidatedTorrentMetaV1Info<ByteBufOwned>,
        files: &'a dyn TorrentStorage,
        file_infos: &'a FileInfos,
    ) -> Self {
        Self {
            torrent,
            files,
            file_infos,
            phantom_data: PhantomData,
        }
    }

    // Returns the bitvector with pieces we have.
    //
    // Uses a small read-ahead pipeline: a dedicated reader thread streams each
    // piece's bytes off disk in large sequential reads (whole file-spans at
    // once) while this thread hashes the previous piece. This keeps the disk
    // continuously busy instead of idling during hashing, and avoids many tiny
    // reads - both matter a lot on spinning disks. Intentionally a SINGLE
    // sequential stream per torrent: parallel reads within one torrent would
    // seek-thrash an HDD. Cross-torrent parallelism is handled by the caller's
    // concurrency limit.
    // Casts below are bounded by piece length (a u32), so they can't truncate.
    #[allow(clippy::cast_possible_truncation)]
    pub fn initial_check(&self, progress: &AtomicU64) -> anyhow::Result<BF> {
        let lengths = *self.torrent.lengths();
        let mut have_pieces =
            BF::from_boxed_slice(vec![0u8; lengths.piece_bitfield_bytes()].into());

        // How many pieces to read ahead. Memory use is roughly
        // (PIPELINE_DEPTH + 1) * default_piece_length per torrent.
        const PIPELINE_DEPTH: usize = 4;
        let piece_buf_len = lengths.default_piece_length() as usize;

        struct PieceData {
            piece_index: ValidPieceIndex,
            buf: Vec<u8>,
            len: usize,
            broken: bool,
        }

        // full: reader -> hasher (filled buffers). empty: hasher -> reader (recycled buffers).
        let (full_tx, full_rx) = std::sync::mpsc::sync_channel::<PieceData>(PIPELINE_DEPTH);
        let (empty_tx, empty_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(PIPELINE_DEPTH + 1);
        for _ in 0..PIPELINE_DEPTH + 1 {
            let _ = empty_tx.send(vec![0u8; piece_buf_len]);
        }

        let files = self.files;
        let file_infos = self.file_infos;

        std::thread::scope(|scope| -> anyhow::Result<()> {
            // Reader thread: walk pieces in order, read each piece into a recycled
            // buffer, hand it to the hasher.
            scope.spawn(move || {
                struct CurrentFile<'a> {
                    index: usize,
                    fi: &'a FileInfo,
                    processed_bytes: u64,
                    is_broken: bool,
                }
                impl CurrentFile<'_> {
                    fn remaining(&self) -> u64 {
                        self.fi.len - self.processed_bytes
                    }
                }
                let mut file_iterator =
                    file_infos.iter().enumerate().map(|(index, fi)| CurrentFile {
                        index,
                        fi,
                        processed_bytes: 0,
                        is_broken: false,
                    });
                let mut current_file = match file_iterator.next() {
                    Some(f) => f,
                    None => return, // empty file list; hasher sees channel close
                };

                for piece_info in lengths.iter_piece_infos() {
                    let mut buf = match empty_rx.recv() {
                        Ok(b) => b,
                        Err(_) => return, // hasher gone
                    };
                    let plen = piece_info.len as usize;
                    if buf.len() < plen {
                        buf.resize(plen, 0);
                    }
                    let mut filled = 0usize;
                    let mut piece_remaining = plen;
                    let mut broken = false;

                    while piece_remaining > 0 {
                        let mut to_read = current_file.remaining().min(piece_remaining as u64) as usize;
                        while to_read == 0 {
                            current_file = match file_iterator.next() {
                                Some(f) => f,
                                None => {
                                    broken = true; // broken torrent metadata
                                    break;
                                }
                            };
                            to_read = current_file.remaining().min(piece_remaining as u64) as usize;
                        }
                        if broken {
                            break;
                        }

                        let pos = current_file.processed_bytes;
                        let dst = &mut buf[filled..filled + to_read];
                        if current_file.fi.attrs.padding {
                            dst.fill(0);
                        } else if current_file.is_broken {
                            broken = true;
                        } else if let Err(err) = files.pread_exact(current_file.index, pos, dst) {
                            debug!(
                                "error reading from file {} ({:?}) at {}: {:#}",
                                current_file.index, current_file.fi.relative_filename, pos, &err
                            );
                            current_file.is_broken = true;
                            broken = true;
                        }
                        filled += to_read;
                        piece_remaining -= to_read;
                        current_file.processed_bytes += to_read as u64;
                    }

                    if full_tx
                        .send(PieceData {
                            piece_index: piece_info.piece_index,
                            buf,
                            len: plen,
                            broken,
                        })
                        .is_err()
                    {
                        return; // hasher gone
                    }
                }
            });

            // Hasher (this thread): hash each piece and compare.
            while let Ok(pd) = full_rx.recv() {
                progress.fetch_add(pd.len as u64, Ordering::Relaxed);
                if pd.broken {
                    trace!("piece {} had read errors, marking as needed", pd.piece_index);
                } else {
                    let mut computed_hash = Sha1::new();
                    computed_hash.update(&pd.buf[..pd.len]);
                    if self
                        .torrent
                        .info()
                        .compare_hash(pd.piece_index.get(), computed_hash.finish())
                        .context("bug: torrent info broken or piece index invalid")?
                    {
                        have_pieces.set(pd.piece_index.get() as usize, true);
                    }
                }
                let _ = empty_tx.send(pd.buf);
            }
            Ok(())
        })?;

        Ok(have_pieces)
    }

    pub fn check_piece(&self, piece_index: ValidPieceIndex) -> anyhow::Result<bool> {
        if cfg!(feature = "_disable_disk_write_net_benchmark") {
            return Ok(true);
        }

        let mut h = Sha1::new();
        let piece_length = self.torrent.lengths().piece_length(piece_index);
        let mut absolute_offset = self.torrent.lengths().piece_offset(piece_index);
        // Read in large chunks (whole file-spans for typical pieces) rather than
        // 64 KiB, capped to bound memory. Same bytes hashed - validation unchanged.
        let mut buf = vec![0u8; std::cmp::min(4 * 1024 * 1024, piece_length as usize)];

        let mut piece_remaining_bytes = piece_length as usize;

        for (file_idx, fi) in self.file_infos.iter().enumerate() {
            let file_len = fi.len;
            if absolute_offset > file_len {
                absolute_offset -= file_len;
                continue;
            }
            let file_remaining_len = file_len - absolute_offset;

            let to_read_in_file: usize =
                std::cmp::min(file_remaining_len, piece_remaining_bytes as u64).try_into()?;
            trace!(
                "piece={}, file_idx={}, seeking to {}",
                piece_index, file_idx, absolute_offset,
            );
            update_hash_from_file(
                file_idx,
                fi,
                absolute_offset,
                self.files,
                &mut h,
                &mut buf,
                to_read_in_file,
            )
            .with_context(|| {
                format!(
                    "error reading {to_read_in_file} bytes, file_id: {file_idx} (\"{:?}\")",
                    fi.relative_filename
                )
            })?;

            piece_remaining_bytes -= to_read_in_file;

            if piece_remaining_bytes == 0 {
                break;
            }

            absolute_offset = 0;
        }

        match self
            .torrent
            .info()
            .compare_hash(piece_index.get(), h.finish())
        {
            Some(true) => {
                trace!("piece={} hash matches", piece_index);
                Ok(true)
            }
            Some(false) => {
                let piece_length = self.torrent.lengths().piece_length(piece_index);
                let absolute_offset = self.torrent.lengths().piece_offset(piece_index);
                warn!(
                    piece_length,
                    absolute_offset, "the piece={} hash does not match", piece_index
                );
                Ok(false)
            }
            None => {
                // this is probably a bug?
                warn!("compare_hash() did not find the piece");
                anyhow::bail!("compare_hash() did not find the piece");
            }
        }
    }

    pub fn read_chunk(
        &self,
        who_sent: PeerHandle,
        chunk_info: &ChunkInfo,
        result_buf: &mut [u8],
    ) -> anyhow::Result<()> {
        if result_buf.len() < chunk_info.size as usize {
            anyhow::bail!("read_chunk(): not enough capacity in the provided buffer")
        }
        let mut absolute_offset = self.torrent.lengths().chunk_absolute_offset(chunk_info);
        let mut buf = result_buf;

        for (file_idx, file_info) in self.file_infos.iter().enumerate() {
            let file_len = file_info.len;
            if absolute_offset > file_len {
                absolute_offset -= file_len;
                continue;
            }
            let file_remaining_len = file_len - absolute_offset;
            let to_read_in_file = std::cmp::min(file_remaining_len, buf.len() as u64).try_into()?;

            trace!(
                "piece={}, handle={}, file_idx={}, seeking to {}. To read chunk: {:?}",
                chunk_info.piece_index, who_sent, file_idx, absolute_offset, &chunk_info
            );
            if file_info.attrs.padding {
                buf[..to_read_in_file].fill(0);
            } else {
                self.files
                    .pread_exact(file_idx, absolute_offset, &mut buf[..to_read_in_file])
                    .with_context(|| {
                        format!("error reading {file_idx} bytes, file_id: {to_read_in_file}")
                    })?;
            }

            buf = &mut buf[to_read_in_file..];

            if buf.is_empty() {
                break;
            }

            absolute_offset = 0;
        }

        Ok(())
    }

    pub fn write_chunk(
        &self,
        who_sent: PeerHandle,
        data: &Piece<ByteBuf<'a>>,
        chunk_info: &ChunkInfo,
    ) -> anyhow::Result<()> {
        let mut absolute_offset = self.torrent.lengths().chunk_absolute_offset(chunk_info);
        let mut data = DoubleBufHelper::new(data.data().0, data.data().1);

        for (file_idx, file_info) in self.file_infos.iter().enumerate() {
            let file_len = file_info.len;
            if absolute_offset > file_len {
                absolute_offset -= file_len;
                continue;
            }

            let remaining_len = file_len - absolute_offset;
            let to_write = std::cmp::min(data.len() as u64, remaining_len).try_into()?;

            trace!(
                "piece={}, chunk={:?}, handle={}, begin={}, file={}, writing {} bytes at {}",
                chunk_info.piece_index,
                chunk_info,
                who_sent,
                chunk_info.offset,
                file_idx,
                to_write,
                absolute_offset
            );
            let slices = data.as_ioslices(to_write);
            debug_assert_eq!(slices[0].len() + slices[1].len(), to_write);
            if !file_info.attrs.padding {
                let written = self
                    .files
                    .pwrite_all_vectored(file_idx, absolute_offset, slices)
                    .with_context(|| {
                        format!(
                            "error writing to file {file_idx} (\"{:?}\")",
                            file_info.relative_filename
                        )
                    })?;
                debug_assert_eq!(written, to_write);
            }
            data.advance(to_write);
            if data.is_empty() {
                break;
            }

            absolute_offset = 0;
        }

        Ok(())
    }
}
