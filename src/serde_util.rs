pub mod string_or_int {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrInt {
            Int(u64),
            String(String),
        }
        let string_or_int = StringOrInt::deserialize(deserializer)?;
        match string_or_int {
            StringOrInt::Int(x) => Ok(x.to_string()),
            StringOrInt::String(s) => Ok(s),
        }
    }
}

pub mod yesno {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match value {
            true => "yes",
            // value of not-yes not documented
            false => "false",
        })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let yesno = String::deserialize(deserializer)?;
        if yesno == "yes" {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub mod stringoneintzero {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(untagged)]
        enum PossibleValues {
            Stringy(String),
            Inty(i64),
        }
        let str_or_int = PossibleValues::deserialize(deserializer)?;
        match &str_or_int {
            PossibleValues::Stringy(x) if x == "1" => Ok(true),
            PossibleValues::Inty(0) => Ok(false),
            x => Err(serde::de::Error::custom(&format!("invalid value {x:?}"))),
        }
    }
}
