use core::ops::{Range, RangeFrom, RangeToInclusive};
use std::{
    borrow::Cow,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use bytesize::ByteSize;
use im::OrdMap;
use itertools::Either;
use libmdbx::{DatabaseFlags, Environment, Geometry, ObjectLength, Stat, WriteFlags};
use log::info;
use snap::raw::{Decoder, Encoder};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use thiserror::Error;
use unwrap_none::UnwrapNone as _;

const GROWTH_STEP: ByteSize = ByteSize::mib(256);
const MAX_NAMED_DATABASES: usize = 10;

#[derive(Clone, Copy)]
pub enum DatabaseMode {
    ReadOnly,
    ReadWrite,
}

impl DatabaseMode {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }

    #[must_use]
    pub const fn mode_permissions(self) -> u16 {
        match self {
            // <https://erthink.github.io/libmdbx/group__c__opening.html#gabb7dd3b10dd31639ba252df545e11768>
            // The UNIX permissions to set on created files. Zero value means to open existing, but do not create.
            Self::ReadOnly => 0,
            Self::ReadWrite => 0o600,
        }
    }

    #[must_use]
    #[cfg(target_os = "linux")]
    pub fn permissions(self) -> u32 {
        self.mode_permissions().into()
    }

    #[must_use]
    #[cfg(not(target_os = "linux"))]
    pub const fn permissions(self) -> u16 {
        self.mode_permissions()
    }
}

pub struct Database(DatabaseKind);

impl Database {
    pub fn persistent(
        name: &str,
        directory: impl AsRef<Path>,
        max_size: ByteSize,
        mode: DatabaseMode,
    ) -> Result<Self> {
        // If a database with the legacy name exists, keep using it.
        // Otherwise, create a new database with the specified name.
        // This check will not force existing users to resync.
        let legacy_name = directory.as_ref().to_str().ok_or(Error)?;

        if !mode.is_read_only() {
            fs_err::create_dir_all(&directory)?;
        }

        // TODO(Grandine Team): The call to `set_max_dbs` and `MAX_NAMED_DATABASES` should be
        //                      unnecessary if the default database is used.
        let environment = Environment::builder()
            .set_max_dbs(MAX_NAMED_DATABASES)
            .set_geometry(Geometry {
                size: Some(..usize::try_from(max_size.as_u64())?),
                growth_step: Some(isize::try_from(GROWTH_STEP.as_u64())?),
                shrink_threshold: None,
                page_size: None,
            })
            .open_with_permissions(directory.as_ref(), mode.permissions())?;

        let transaction = environment.begin_rw_txn()?;
        let existing_db = transaction.open_db(Some(legacy_name));

        let database_name = if existing_db.is_err() {
            info!("database: {legacy_name} with name {name}");
            if !mode.is_read_only() {
                transaction.create_db(Some(name), DatabaseFlags::default())?;
            }

            name
        } else {
            info!("legacy database: {legacy_name}");
            legacy_name
        }
        .to_owned();

        transaction.commit()?;

        Ok(Self(DatabaseKind::Persistent {
            database_name,
            environment,
        }))
    }

    #[must_use]
    pub fn in_memory() -> Self {
        Self(DatabaseKind::InMemory {
            map: Mutex::default(),
        })
    }

    pub fn delete(&self, key: impl AsRef<[u8]>) -> Result<()> {
        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_rw_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                let mut cursor = transaction.cursor(&database)?;

                if cursor.set::<()>(key.as_ref())?.is_some() {
                    cursor.del(WriteFlags::default())?;
                    transaction.commit()?;
                }
            }
            DatabaseKind::InMemory { map } => {
                map.lock()
                    .expect("in-memory database mutex is poisoned")
                    .remove(key.as_ref());
            }
        }

        Ok(())
    }

    pub fn delete_range(&self, range: Range<impl AsRef<[u8]>>) -> Result<()> {
        let start = range.start.as_ref();
        let end = range.end.as_ref();

        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_rw_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                let mut cursor = transaction.cursor(&database)?;

                let Some((mut key, ())) = cursor.set_range::<Cow<_>, _>(start)? else {
                    return Ok(());
                };

                while *key < *end {
                    cursor.del(WriteFlags::default())?;
                    match cursor.next::<Cow<_>, _>()? {
                        Some((new_key, ())) => key = new_key,
                        None => break,
                    }
                }

                transaction.commit()?;
            }
            DatabaseKind::InMemory { map } => {
                // Update the map atomically for consistency with `Database::put_batch`.
                // This should only make a difference if the method panics between mutations.
                // The mutex will be left poisoned either way.
                let mut map = map.lock().expect("in-memory database mutex is poisoned");
                let mut new_map = map.clone();

                let end_pair = map.get_key_value(end);
                let (below, _) = new_map.split(start);
                let (_, above) = new_map.split(end);

                new_map = below.union(above);

                if let Some((key, value)) = end_pair {
                    new_map
                        .insert(key.clone_arc(), value.clone_arc())
                        .expect_none("end_pair should have been discarded by OrdMap::split");
                }

                *map = new_map;
            }
        }

        Ok(())
    }

    pub fn contains_key(&self, key: impl AsRef<[u8]>) -> Result<bool> {
        let contains_key = match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;
                transaction
                    .get::<()>(database.dbi(), key.as_ref())?
                    .is_some()
            }
            DatabaseKind::InMemory { map } => map
                .lock()
                .expect("in-memory database mutex is poisoned")
                .contains_key(key.as_ref()),
        };

        Ok(contains_key)
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                transaction
                    .get::<Cow<_>>(database.dbi(), key.as_ref())?
                    .map(|compressed| decompress(&compressed))
            }
            DatabaseKind::InMemory { map } => map
                .lock()
                .expect("in-memory database mutex is poisoned")
                .get(key.as_ref())
                .map(|compressed| decompress(compressed)),
        }
        .transpose()
    }

    pub fn db_stats(&self) -> Result<Option<Stat>> {
        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                Some(transaction.db_stat(&database)?)
            }
            DatabaseKind::InMemory { map: _ } => None,
        }
        .pipe(Ok)
    }

    pub fn iterate_all_keys_with_lengths(
        &self,
    ) -> Result<impl Iterator<Item = Result<(Cow<[u8]>, usize)>>> {
        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                let mut cursor = transaction.cursor(&database)?;

                core::iter::from_fn(move || cursor.next().transpose())
                    .map(|result| {
                        let (key, ObjectLength(length)) = result?;
                        Ok((key, length))
                    })
                    .pipe(Either::Left)
            }
            DatabaseKind::InMemory { map } => {
                let map = map.lock().expect("in-memory database mutex is poisoned");

                map.clone()
                    .into_iter()
                    .map(|(key, value)| Ok((Cow::Owned(key.to_vec()), value.len())))
                    .pipe(Either::Right)
            }
        }
        .pipe(Ok)
    }

    #[expect(clippy::type_complexity)]
    pub fn iterator_ascending(
        &self,
        range: RangeFrom<impl AsRef<[u8]>>,
    ) -> Result<impl Iterator<Item = Result<(Cow<[u8]>, Vec<u8>)>>> {
        let start = range.start.as_ref();

        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                let mut cursor = transaction.cursor(&database)?;

                cursor
                    .set_range(start)
                    .transpose()
                    .into_iter()
                    .chain(core::iter::from_fn(move || cursor.next().transpose()))
                    .map(|result| decompress_pair(result?))
                    .pipe(Either::Left)
            }
            DatabaseKind::InMemory { map } => {
                let map = map.lock().expect("in-memory database mutex is poisoned");
                let start_pair = map.get_key_value(start);
                let (_, mut above) = map.split(start);

                if let Some((key, value)) = start_pair {
                    above
                        .insert(key.clone_arc(), value.clone_arc())
                        .expect_none("start_pair should have been discarded by OrdMap::split");
                }

                above
                    .into_iter()
                    .map(|(key, value)| Ok((Cow::Owned(key.to_vec()), decompress(value.as_ref())?)))
                    .pipe(Either::Right)
            }
        }
        .pipe(Ok)
    }

    #[expect(clippy::type_complexity)]
    pub fn iterator_descending(
        &self,
        range: RangeToInclusive<impl AsRef<[u8]>>,
    ) -> Result<impl Iterator<Item = Result<(Cow<[u8]>, Vec<u8>)>>> {
        let end = range.end.as_ref();

        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                let mut cursor = transaction.cursor(&database)?;

                cursor
                    .set_key(end)
                    .transpose()
                    .into_iter()
                    .chain(core::iter::from_fn(move || cursor.prev().transpose()))
                    .map(|result| decompress_pair(result?))
                    .pipe(Either::Left)
            }
            DatabaseKind::InMemory { map } => {
                let map = map.lock().expect("in-memory database mutex is poisoned");
                let end_pair = map.get_key_value(end);
                let (mut below, _) = map.split(end);

                if let Some((key, value)) = end_pair {
                    below
                        .insert(key.clone_arc(), value.clone_arc())
                        .expect_none("end_pair should have been discarded by OrdMap::split");
                }

                below
                    .into_iter()
                    .rev()
                    .map(|(key, value)| Ok((Cow::Owned(key.to_vec()), decompress(value.as_ref())?)))
                    .pipe(Either::Right)
            }
        }
        .pipe(Ok)
    }

    pub fn put(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<()> {
        self.put_batch(core::iter::once((key, value)))
    }

    pub fn put_batch(
        &self,
        pairs: impl IntoIterator<Item = (impl AsRef<[u8]>, impl AsRef<[u8]>)>,
    ) -> Result<()> {
        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_rw_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                for (key, value) in pairs {
                    let key = key.as_ref();
                    let compressed = compress(value.as_ref())?;
                    transaction.put(database.dbi(), key, compressed, WriteFlags::default())?;
                }

                transaction.commit()?;
            }
            DatabaseKind::InMemory { map } => {
                let mut map = map.lock().expect("in-memory database mutex is poisoned");
                let mut new_map = map.clone();

                for (key, value) in pairs {
                    let key = key.as_ref().into();
                    let compressed = compress(value.as_ref())?.into();
                    new_map.insert(key, compressed);
                }

                *map = new_map;
            }
        }

        Ok(())
    }

    /// Returns the first key-value pair whose key is less than or equal to `key`.
    ///
    /// Behaves like [`im::OrdMap::get_prev`].
    ///
    /// [`im::OrdMap::get_prev`]: https://docs.rs/im/15.1.0/im/ordmap/struct.OrdMap.html#method.get_prev
    pub fn prev(&self, key: impl AsRef<[u8]>) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                let mut cursor = transaction.cursor(&database)?;

                cursor
                    .set_key(key.as_ref())
                    .transpose()
                    .or_else(|| cursor.prev().transpose())
                    .transpose()?
                    .map(decompress_pair)
            }
            DatabaseKind::InMemory { map } => map
                .lock()
                .expect("in-memory database mutex is poisoned")
                .get_prev(key.as_ref())
                .map(|(key, value)| Ok((key.to_vec(), decompress(value)?))),
        }
        .transpose()
    }

    /// Returns the first key-value pair whose key is greater than or equal to `key`.
    ///
    /// Behaves like [`im::OrdMap::get_next`].
    ///
    /// [`im::OrdMap::get_next`]: https://docs.rs/im/15.1.0/im/ordmap/struct.OrdMap.html#method.get_next
    pub fn next(&self, key: impl AsRef<[u8]>) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match self.kind() {
            DatabaseKind::Persistent {
                database_name,
                environment,
            } => {
                let transaction = environment.begin_ro_txn()?;
                let database = transaction.open_db(Some(database_name))?;

                let mut cursor = transaction.cursor(&database)?;

                cursor.set_range(key.as_ref())?.map(decompress_pair)
            }
            DatabaseKind::InMemory { map } => map
                .lock()
                .expect("in-memory database mutex is poisoned")
                .get_next(key.as_ref())
                .map(|(key, value)| Ok((key.to_vec(), decompress(value)?))),
        }
        .transpose()
    }

    const fn kind(&self) -> &DatabaseKind {
        &self.0
    }
}

enum DatabaseKind {
    Persistent {
        // TODO(Grandine Team): It should be possible to remove `database_name` by using the default
        //                      database (`None`), but that would probably force users to resync.
        database_name: String,
        environment: Environment,
    },
    InMemory {
        // Various methods of `OrdMap` and `Database` clone the elements of this map,
        // so they should be cheaply cloneable. This disqualifies `Vec<u8>` and `Box<[u8]>`.
        //
        // Various methods of `Database` return keys in the form of `Vec<u8>` or `Cow<[u8]>`.
        // Converting between them and `Arc<[u8]>` is costly due to the reference count before data.
        // Returning `Arc<[u8]>` from the methods would require a conversion in the persistent case
        // because `libmdbx` cannot decode directly into `std::sync::Arc` or `triomphe::Arc`.
        //
        // `Bytes` can be cheaply converted to and from `Vec<u8>` if its capacity equals its length,
        // but `Database` cannot benefit from that with its current API.
        // Returning a `Vec<u8>` or `Cow<u8>` requires copying due to shared ownership.
        // Writing requires copying due to the signature of `Database::put`.
        //
        // Some versions of `libmdbx` (including the one from `reth-libmdbx`) can decode into
        // `lifetimed_bytes::Bytes`, which functions like `Cow<[u8]>`, but with the internal
        // representation of `Bytes`. `lifetimed_bytes::Bytes` is necessarily distinct from
        // `bytes::Bytes`, which makes it harder to use.
        map: Mutex<InMemoryMap>,
    },
}

#[derive(Debug, Error)]
#[error("database directory path should be a valid Unicode string")]
struct Error;

type InMemoryMap = OrdMap<Arc<[u8]>, Arc<[u8]>>;

fn compress(data: &[u8]) -> Result<Vec<u8>> {
    Encoder::new().compress_vec(data).map_err(Into::into)
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    Decoder::new().decompress_vec(data).map_err(Into::into)
}

fn decompress_pair<K>((key, compressed_value): (K, Cow<[u8]>)) -> Result<(K, Vec<u8>)> {
    let value = decompress(&compressed_value)?;
    Ok((key, value))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use test_case::test_case;

    use super::*;

    type Constructor = fn() -> Result<Database>;

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_delete(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        database.delete("C")?;
        database.delete("D")?;

        assert_pairs_eq(
            database.iterator_ascending("A"..)?,
            [("A", "1"), ("B", "2"), ("E", "5")],
        )?;

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_delete_range_inclusive_exclusive(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        database.delete_range("B".."C")?;

        assert_pairs_eq(
            database.iterator_ascending("A"..)?,
            [("A", "1"), ("C", "3"), ("E", "5")],
        )?;

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_delete_range_between(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        database.delete_range("D".."F")?;

        assert_pairs_eq(
            database.iterator_ascending("A"..)?,
            [("A", "1"), ("B", "2"), ("C", "3")],
        )?;

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_contains_key(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        assert!(database.contains_key("A")?);
        assert!(database.contains_key("B")?);
        assert!(database.contains_key("C")?);
        assert!(!database.contains_key("D")?);
        assert!(database.contains_key("E")?);
        assert!(!database.contains_key("F")?);

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_iterator_ascending(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        assert_pairs_eq(
            database.iterator_ascending("0"..)?,
            [("A", "1"), ("B", "2"), ("C", "3"), ("E", "5")],
        )?;

        assert_pairs_eq(
            database.iterator_ascending("A"..)?,
            [("A", "1"), ("B", "2"), ("C", "3"), ("E", "5")],
        )?;

        assert_pairs_eq(
            database.iterator_ascending("B"..)?,
            [("B", "2"), ("C", "3"), ("E", "5")],
        )?;

        assert_pairs_eq(
            database.iterator_ascending("C"..)?,
            [("C", "3"), ("E", "5")],
        )?;

        assert_pairs_eq(database.iterator_ascending("D"..)?, [("E", "5")])?;
        assert_pairs_eq(database.iterator_ascending("E"..)?, [("E", "5")])?;
        assert_pairs_eq(database.iterator_ascending("F"..)?, [])?;

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_iterator_descending(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        assert_pairs_eq(
            database.iterator_descending(..="F")?,
            [("E", "5"), ("C", "3"), ("B", "2"), ("A", "1")],
        )?;

        assert_pairs_eq(
            database.iterator_descending(..="E")?,
            [("E", "5"), ("C", "3"), ("B", "2"), ("A", "1")],
        )?;

        assert_pairs_eq(
            database.iterator_descending(..="D")?,
            [("C", "3"), ("B", "2"), ("A", "1")],
        )?;

        assert_pairs_eq(
            database.iterator_descending(..="C")?,
            [("C", "3"), ("B", "2"), ("A", "1")],
        )?;

        assert_pairs_eq(
            database.iterator_descending(..="B")?,
            [("B", "2"), ("A", "1")],
        )?;

        assert_pairs_eq(database.iterator_descending(..="A")?, [("A", "1")])?;
        assert_pairs_eq(database.iterator_descending(..="0")?, [])?;

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_all_keys_iterator_with_lengths(constructor: Constructor) -> Result<()> {
        let database = constructor()?;
        let values = database
            .iterate_all_keys_with_lengths()?
            .map(|result| {
                let (key, length) = result?;
                let key_string = core::str::from_utf8(key.as_ref())?;
                Ok((key_string.to_owned(), length))
            })
            .collect::<Result<Vec<_>>>()?;

        let compressed_len = compress(b"A")?.len();
        assert_eq!(compressed_len, 3);

        let expected = [
            ("A".to_owned(), compressed_len),
            ("B".to_owned(), compressed_len),
            ("C".to_owned(), compressed_len),
            ("E".to_owned(), compressed_len),
        ];

        assert_eq!(values, expected);

        Ok(())
    }

    // This covers a bug we introduced and fixed while implementing in-memory mode.
    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_iterators_do_not_modify_the_database(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        assert_pairs_eq(database.iterator_ascending("E"..)?, [("E", "5")])?;
        assert_pairs_eq(database.iterator_ascending("E"..)?, [("E", "5")])?;

        assert_pairs_eq(database.iterator_ascending("F"..)?, [])?;
        assert_pairs_eq(database.iterator_ascending("F"..)?, [])?;

        assert_pairs_eq(database.iterator_descending(..="A")?, [("A", "1")])?;
        assert_pairs_eq(database.iterator_descending(..="A")?, [("A", "1")])?;

        assert_pairs_eq(database.iterator_descending(..="0")?, [])?;
        assert_pairs_eq(database.iterator_descending(..="0")?, [])?;

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_multiple_of_the_same_key(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        database.put_batch([("A", "1"), ("A", "2"), ("A", "3")])?;

        assert_eq!(database.get("A")?, Some(to_bytes("3")));

        Ok(())
    }

    // ```text
    // 0 A B C D E F
    //   │ │ ├─┘ ├─┘
    //   A B C   E
    // ```
    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_prev(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        assert!("0" < "A");

        assert_eq!(database.prev("0")?, None);
        assert_eq!(database.prev("A")?, Some(to_bytes_pair(("A", "1"))));
        assert_eq!(database.prev("B")?, Some(to_bytes_pair(("B", "2"))));
        assert_eq!(database.prev("C")?, Some(to_bytes_pair(("C", "3"))));
        assert_eq!(database.prev("D")?, Some(to_bytes_pair(("C", "3"))));
        assert_eq!(database.prev("E")?, Some(to_bytes_pair(("E", "5"))));
        assert_eq!(database.prev("F")?, Some(to_bytes_pair(("E", "5"))));

        Ok(())
    }

    // ```text
    // 0 A B C D E F
    // └─┤ │ │ └─┤
    //   A B C   E
    // ```
    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_next(constructor: Constructor) -> Result<()> {
        let database = constructor()?;

        assert!("0" < "A");

        assert_eq!(database.next("0")?, Some(to_bytes_pair(("A", "1"))));
        assert_eq!(database.next("A")?, Some(to_bytes_pair(("A", "1"))));
        assert_eq!(database.next("B")?, Some(to_bytes_pair(("B", "2"))));
        assert_eq!(database.next("C")?, Some(to_bytes_pair(("C", "3"))));
        assert_eq!(database.next("D")?, Some(to_bytes_pair(("E", "5"))));
        assert_eq!(database.next("E")?, Some(to_bytes_pair(("E", "5"))));
        assert_eq!(database.next("F")?, None);

        Ok(())
    }

    #[test_case(build_persistent_database)]
    #[test_case(build_in_memory_database)]
    fn test_isolation(constructor: Constructor) -> Result<()> {
        let database = constructor()?;
        let iterator = database.iterator_ascending("A"..)?;

        database.delete_range("A".."F")?;

        assert_pairs_eq(iterator, [("A", "1"), ("B", "2"), ("C", "3"), ("E", "5")])?;

        Ok(())
    }

    fn build_persistent_database() -> Result<Database> {
        let database = Database::persistent(
            "test_db",
            TempDir::new()?,
            ByteSize::mib(1),
            DatabaseMode::ReadWrite,
        )?;

        populate_database(&database)?;
        Ok(database)
    }

    fn build_in_memory_database() -> Result<Database> {
        let database = Database::in_memory();
        populate_database(&database)?;
        Ok(database)
    }

    fn populate_database(database: &Database) -> Result<()> {
        // This indirectly tests `Database::put` and `Database::put_batch`.
        database.put_batch([("A", "1"), ("B", "2"), ("C", "3")])?;
        database.put("E", "5")?;
        Ok(())
    }

    fn assert_pairs_eq<'strings>(
        actual_pairs: impl IntoIterator<Item = Result<(impl AsRef<[u8]>, impl AsRef<[u8]>)>>,
        expected_pairs: impl IntoIterator<Item = (&'strings str, &'strings str)>,
    ) -> Result<()> {
        let actual_pairs = to_string_pairs(actual_pairs)?;
        let expected_pairs = to_string_pairs(expected_pairs.into_iter().map(Ok))?;

        assert_eq!(actual_pairs, expected_pairs);

        Ok(())
    }

    fn to_string_pairs(
        pairs: impl IntoIterator<Item = Result<(impl AsRef<[u8]>, impl AsRef<[u8]>)>>,
    ) -> Result<Vec<(String, String)>> {
        pairs
            .into_iter()
            .map(|result| {
                let (key, value) = result?;
                let key_string = core::str::from_utf8(key.as_ref())?;
                let value_string = core::str::from_utf8(value.as_ref())?;
                Ok((key_string.to_owned(), value_string.to_owned()))
            })
            .collect()
    }

    fn to_bytes_pair((key, value): (&str, &str)) -> (Vec<u8>, Vec<u8>) {
        (to_bytes(key), to_bytes(value))
    }

    fn to_bytes(string: &str) -> Vec<u8> {
        string.as_bytes().to_vec()
    }
}
