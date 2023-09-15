use std::collections::{hash_map::Keys, HashMap};

pub trait KeyValueStore: Send + Sync {
    type Key;
    type Value;

    fn set(&mut self, key: Self::Key, value: Self::Value) -> &Self::Key;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
    fn del(&mut self, key: &Self::Key) -> Option<Self::Value>;
    fn list<'kvs>(&'kvs self) -> Box<dyn Iterator<Item = &'kvs Self::Key> + 'kvs>;
}

impl<K, V> KeyValueStore for HashMap<K, V>
where
    K: Send + Sync + Eq + std::hash::Hash + Clone,
    V: Send + Sync,
{
    type Key = K;
    type Value = V;

    fn set(&mut self, key: Self::Key, value: Self::Value) -> &Self::Key {
        self.insert(key.clone(), value);
        return self.get_key_value(&key).unwrap().0;
    }

    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.get(key)
    }

    fn del(&mut self, key: &Self::Key) -> Option<Self::Value> {
        self.remove(key)
    }

    fn list<'kvs>(&'kvs self) -> Box<dyn Iterator<Item = &'kvs Self::Key> + 'kvs> {
        let keys: Box<Keys<'kvs, K, V>> = Box::new(self.keys());
        let keys: Box<dyn Iterator<Item = &'kvs Self::Key> + 'kvs> =
            keys as Box<dyn Iterator<Item = &'kvs K> + 'kvs>;
        return keys;
    }
}
