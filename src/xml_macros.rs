macro_rules! unwrap_vec {
    ($fn_name:ident, $item_type:ty, $rename:literal) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<Vec<$item_type>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            struct Wrapper {
                #[serde(rename = $rename, default)]
                items: Vec<$item_type>,
            }
            Ok(Wrapper::deserialize(deserializer)?.items)
        }
    };
}
