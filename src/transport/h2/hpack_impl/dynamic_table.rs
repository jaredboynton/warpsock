//! HPACK dynamic table (RFC 7541 Section 2.3.2).
//!
//! The dynamic table is a FIFO buffer that stores recently used header fields
//! to improve compression efficiency.

use super::static_table::bytes_eq_ignore_ascii_case;

/// Dynamic table entry.
#[derive(Clone)]
pub struct DynamicEntry {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl DynamicEntry {
    /// Create a new dynamic entry.
    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Self {
        Self { name, value }
    }

    /// Get the name.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Get the value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Calculate the size of this entry per RFC 7541 Section 4.1.
    ///
    /// Size = 32 + len(name) + len(value)
    pub fn size(&self) -> usize {
        32 + self.name.len() + self.value.len()
    }
}

/// Dynamic table with FIFO eviction.
pub struct DynamicTable {
    entries: Vec<DynamicEntry>,
    max_size: usize,
    current_size: usize,
}

impl DynamicTable {
    /// Create a new dynamic table with the specified maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_size,
            current_size: 0,
        }
    }

    /// Set the maximum table size.
    ///
    /// This will evict entries if necessary to meet the new size limit.
    pub fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.evict_to_max_size();
    }

    // The following inspection methods are marked with #[allow(dead_code)] because
    // they are part of the public API and useful for debugging/inspection, even
    // though they are not currently used within the library code itself. They are
    // used in tests and may be used by library consumers.

    /// Get the current maximum size.
    #[allow(dead_code)]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Get the current table size in bytes.
    #[allow(dead_code)]
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Get the number of entries.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an entry by dynamic index.
    ///
    /// Dynamic indices start at 1 (for the first/newest entry).
    /// This function expects the index relative to the dynamic table,
    /// not the combined index space.
    pub fn get(&self, index: usize) -> Option<&DynamicEntry> {
        if index == 0 || index > self.entries.len() {
            return None;
        }
        // Dynamic table: newest entry is at index 0, oldest at len()-1
        // But HPACK indices: newest entry is at lowest index (1)
        // So index 1 -> entries[0], index 2 -> entries[1], etc.
        self.entries.get(index - 1)
    }

    /// Find an entry by name and value.
    ///
    /// Returns the dynamic index (1-based) if found.
    pub fn find(&self, name: &[u8], value: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| bytes_eq_ignore_ascii_case(e.name(), name) && e.value() == value)
            .map(|idx| idx + 1)
    }

    /// Find an entry by name only.
    ///
    /// Returns the first matching dynamic index (1-based) if found.
    pub fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| bytes_eq_ignore_ascii_case(e.name(), name))
            .map(|idx| idx + 1)
    }

    /// Add a new entry to the dynamic table.
    ///
    /// The entry is added at the beginning (lowest index).
    /// Old entries are evicted if necessary to make room.
    pub fn add(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry = DynamicEntry::new(name, value);
        let entry_size = entry.size();

        // Evict entries until we have room
        while self.current_size + entry_size > self.max_size && !self.entries.is_empty() {
            self.evict_oldest();
        }

        // If entry is larger than max_size, empty the table per RFC 7541 Section 4.4
        if entry_size > self.max_size {
            self.entries.clear();
            self.current_size = 0;
            return;
        }

        // Add entry at the beginning
        self.entries.insert(0, entry);
        self.current_size += entry_size;
    }

    /// Evict entries until the table size is <= max_size.
    fn evict_to_max_size(&mut self) {
        while self.current_size > self.max_size && !self.entries.is_empty() {
            self.evict_oldest();
        }
    }

    /// Evict the oldest entry (last in the vector).
    fn evict_oldest(&mut self) {
        if let Some(entry) = self.entries.pop() {
            self.current_size -= entry.size();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_table_add() {
        let mut table = DynamicTable::new(4096);
        table.add(b"custom-key".to_vec(), b"custom-value".to_vec());

        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());

        let entry = table.get(1).unwrap();
        assert_eq!(entry.name(), b"custom-key");
        assert_eq!(entry.value(), b"custom-value");
    }

    #[test]
    fn test_dynamic_table_fifo() {
        let mut table = DynamicTable::new(4096);
        table.add(b"first".to_vec(), b"value1".to_vec());
        table.add(b"second".to_vec(), b"value2".to_vec());

        // Newest entry should be at index 1
        assert_eq!(table.get(1).unwrap().name(), b"second");
        assert_eq!(table.get(2).unwrap().name(), b"first");
    }

    #[test]
    fn test_dynamic_table_eviction() {
        let mut table = DynamicTable::new(100);
        // Add entries until eviction occurs
        for i in 0..10 {
            table.add(
                format!("name{}", i).into_bytes(),
                format!("value{}", i).into_bytes(),
            );
        }

        // Table should have evicted some entries
        assert!(table.current_size() <= 100);
    }

    #[test]
    fn test_dynamic_table_find() {
        let mut table = DynamicTable::new(4096);
        table.add(b"custom-key".to_vec(), b"custom-value".to_vec());

        assert_eq!(table.find(b"custom-key", b"custom-value"), Some(1));
        assert_eq!(table.find(b"custom-key", b"other-value"), None);
        assert_eq!(table.find_by_name(b"custom-key"), Some(1));
    }

    #[test]
    fn test_dynamic_table_size_reduction() {
        let mut table = DynamicTable::new(4096);
        assert_eq!(table.max_size(), 4096);

        table.add(b"name1".to_vec(), b"value1".to_vec());
        table.add(b"name2".to_vec(), b"value2".to_vec());

        let initial_size = table.current_size();
        table.set_max_size(50);
        assert_eq!(table.max_size(), 50);

        // Should have evicted entries
        assert!(table.current_size() <= 50);
        assert!(table.current_size() < initial_size);
    }
}
