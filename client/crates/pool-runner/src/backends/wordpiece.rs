//! BERT WordPiece tokenizer (uncased by default, as all-MiniLM / bge-small / e5-small use), implemented
//! in-crate so the runner needs no tokenizer library or network access. Reads `vocab.txt` from the bundle.

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

pub struct WordPiece {
    vocab: HashMap<String, u32>,
    pub cls: u32,
    pub sep: u32,
    pub pad: u32,
    unk: u32,
    lowercase: bool,
    pub max_len: usize,
}

fn is_punct(c: char) -> bool {
    c.is_ascii_punctuation() || (!c.is_alphanumeric() && !c.is_whitespace() && !c.is_control())
}

fn is_cjk(c: char) -> bool {
    matches!(c as u32,
        0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0x20000..=0x2A6DF | 0x2A700..=0x2B73F |
        0x2B740..=0x2B81F | 0x2B820..=0x2CEAF | 0xF900..=0xFAFF | 0x2F800..=0x2FA1F)
}

impl WordPiece {
    pub fn from_vocab_txt(text: &str, lowercase: bool, max_len: usize) -> Result<Self, String> {
        let vocab: HashMap<String, u32> =
            text.lines().enumerate().map(|(i, l)| (l.trim_end_matches('\r').to_string(), i as u32)).collect();
        let id = |t: &str| vocab.get(t).copied().ok_or_else(|| format!("vocab lacks {t}"));
        Ok(Self {
            cls: id("[CLS]")?,
            sep: id("[SEP]")?,
            pad: id("[PAD]")?,
            unk: id("[UNK]")?,
            vocab,
            lowercase,
            max_len: max_len.max(2),
        })
    }

    fn basic_tokens(&self, text: &str) -> Vec<String> {
        let mut cleaned = String::with_capacity(text.len());
        for c in text.chars() {
            if c == '\u{0}' || c == '\u{fffd}' || (c.is_control() && !c.is_whitespace()) {
                continue;
            }
            if is_cjk(c) {
                cleaned.push(' ');
                cleaned.push(c);
                cleaned.push(' ');
            } else {
                cleaned.push(if c.is_whitespace() { ' ' } else { c });
            }
        }
        let mut out = Vec::new();
        for word in cleaned.split_whitespace() {
            let word: String = if self.lowercase {
                // lowercase + strip accents (NFD, drop combining marks)
                word.to_lowercase().nfd().filter(|c| !unicode_normalization::char::is_combining_mark(*c)).collect()
            } else {
                word.to_string()
            };
            let mut cur = String::new();
            for c in word.chars() {
                if is_punct(c) {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                    out.push(c.to_string());
                } else {
                    cur.push(c);
                }
            }
            if !cur.is_empty() {
                out.push(cur);
            }
        }
        out
    }

    fn wordpiece(&self, word: &str, out: &mut Vec<u32>) {
        let chars: Vec<char> = word.chars().collect();
        if chars.len() > 100 {
            out.push(self.unk);
            return;
        }
        let mut pieces = Vec::new();
        let mut start = 0;
        while start < chars.len() {
            let mut end = chars.len();
            let mut found = None;
            while start < end {
                let mut sub: String = chars[start..end].iter().collect();
                if start > 0 {
                    sub = format!("##{sub}");
                }
                if let Some(&id) = self.vocab.get(&sub) {
                    found = Some(id);
                    break;
                }
                end -= 1;
            }
            match found {
                Some(id) => {
                    pieces.push(id);
                    start = end;
                }
                None => {
                    out.push(self.unk);
                    return;
                }
            }
        }
        out.extend(pieces);
    }

    /// `[CLS] tokens... [SEP]`, truncated to `max_len`.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let mut ids = vec![self.cls];
        for w in self.basic_tokens(text) {
            self.wordpiece(&w, &mut ids);
            if ids.len() >= self.max_len - 1 {
                ids.truncate(self.max_len - 1);
                break;
            }
        }
        ids.push(self.sep);
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_like_bert_uncased() {
        let vocab = "[PAD]\n[UNK]\n[CLS]\n[SEP]\nhello\nworld\n,\n!\nun\n##aff\n##able\ncafe\n";
        let wp = WordPiece::from_vocab_txt(vocab, true, 16).unwrap();
        assert_eq!(wp.encode("Hello, WORLD!"), vec![2, 4, 6, 5, 7, 3]);
        assert_eq!(wp.encode("unaffable"), vec![2, 8, 9, 10, 3]);
        assert_eq!(wp.encode("Café"), vec![2, 11, 3]);
        assert_eq!(wp.encode("zzz"), vec![2, 1, 3]);
        // truncation keeps [CLS] ... [SEP]
        let long = "hello ".repeat(100);
        let ids = wp.encode(&long);
        assert_eq!(ids.len(), 16);
        assert_eq!((ids[0], ids[15]), (2, 3));
    }
}
