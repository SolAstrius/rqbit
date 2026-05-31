use crate::{api::TorrentIdOrHash, bitv::BitV, type_aliases::BF};

#[async_trait::async_trait]
pub trait BitVFactory: Send + Sync {
    async fn load(&self, id: TorrentIdOrHash) -> anyhow::Result<Option<Box<dyn BitV>>>;
    async fn clear(&self, id: TorrentIdOrHash) -> anyhow::Result<()>;
    async fn store_initial_check(
        &self,
        id: TorrentIdOrHash,
        b: BF,
    ) -> anyhow::Result<Box<dyn BitV>>;

    /// Last-modified time of the persisted bitfield, used as the reference
    /// "as-of" timestamp for the opt-in fastresume trust path. Default: None
    /// (trust won't engage on backends that can't report it).
    async fn last_modified(
        &self,
        _id: TorrentIdOrHash,
    ) -> anyhow::Result<Option<std::time::SystemTime>> {
        Ok(None)
    }
}

pub struct NonPersistentBitVFactory {}

#[async_trait::async_trait]
impl BitVFactory for NonPersistentBitVFactory {
    async fn load(&self, _: TorrentIdOrHash) -> anyhow::Result<Option<Box<dyn BitV>>> {
        Ok(None)
    }

    async fn clear(&self, _id: TorrentIdOrHash) -> anyhow::Result<()> {
        Ok(())
    }

    async fn store_initial_check(
        &self,
        _id: TorrentIdOrHash,
        b: BF,
    ) -> anyhow::Result<Box<dyn BitV>> {
        Ok(Box::new(b))
    }
}
