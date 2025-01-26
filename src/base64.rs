pub struct Base64 {
    encoded: String,
}

impl Base64 {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn new<T: AsRef<[u8]>>(input: T) -> Self {
        let bytes = input.as_ref();
        let mut output = Vec::with_capacity((bytes.len() + 2) / 3 * 4);
        let chunks = bytes.chunks(3);

        for chunk in chunks {
            let b1 = chunk[0];
            let b2 = chunk.get(1).copied().unwrap_or(0);
            let b3 = chunk.get(2).copied().unwrap_or(0);

            let c1 = Self::BASE64_CHARS[(b1 >> 2) as usize];
            let c2 = Self::BASE64_CHARS[((b1 & 0x03) << 4 | (b2 >> 4)) as usize];
            
            let c3 = if chunk.len() > 1 {
                Self::BASE64_CHARS[((b2 & 0x0F) << 2 | (b3 >> 6)) as usize]
            } else {
                b'='
            };

            let c4 = if chunk.len() > 2 {
                Self::BASE64_CHARS[(b3 & 0x3F) as usize]
            } else {
                b'='
            };

            output.extend_from_slice(&[c1, c2, c3, c4]);
        }

        let encoded = String::from_utf8(output).expect("Invalid UTF-8 sequence");
        Self { encoded }
    }

    pub fn base64_url(&self) -> String {
        self.encoded
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "")
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encoding() {
        let input = "Hello, World!";
        let base64 = Base64::new(input);
        assert_eq!(base64.as_str(), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_url_safe_encoding() {
        let input = "Hello+World/123=";
        let base64 = Base64::new(input);
        let url_safe = base64.base64_url();
        assert!(!url_safe.contains('+'));
        assert!(!url_safe.contains('/'));
        assert!(!url_safe.contains('='));
    }

    #[test]
    fn test_different_lengths() {
        let base64 = Base64::new("a");
        assert_eq!(base64.as_str(), "YQ==");

        let base64 = Base64::new("ab");
        assert_eq!(base64.as_str(), "YWI=");

        let base64 = Base64::new("abc");
        assert_eq!(base64.as_str(), "YWJj");
    }

    #[test]
    fn test_binary_data() {
        let input = vec![0xFF, 0x00, 0xFF];
        let base64 = Base64::new(input);
        assert_eq!(base64.as_str(), "/wD/");
    }
}
