//! Which release (T-375): the tag that `--version` names, else the newest
//! of the repository's releases, from GitHub's API or, where that fails (it
//! allows 60 calls an hour to an address with no token), from the
//! releases' Atom feed. A tag with `-` in it is a prerelease, as the release
//! workflow marks one, and only a prerelease looks at another.

use std::cmp::Ordering;

/// A version of semver's form, ordered as semver orders them: `1.0.0-beta.2`
/// before `1.0.0-beta.10`, and each prerelease before its release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    core: [u64; 3],
    pre: Vec<Ident>,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Number(u64),
    Text(String),
}

impl Version {
    /// `MAJOR.MINOR.PATCH[-PRE][+BUILD]`, the build ignored as semver
    /// ignores it.
    pub fn parse(text: &str) -> Option<Version> {
        let plain = text.split('+').next()?;
        let (core, pre) = match plain.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (plain, None),
        };
        let numbers: Vec<u64> = core.split('.').map(number).collect::<Option<_>>()?;
        let core: [u64; 3] = numbers.try_into().ok()?;
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre.split('.').map(ident).collect::<Option<_>>()?,
        };
        Some(Version { core, pre, text: plain.to_string() })
    }

    /// The version of a tag `vVERSION`.
    pub fn of_tag(tag: &str) -> Option<Version> {
        Version::parse(tag.strip_prefix('v')?)
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    /// The tag of this version.
    pub fn tag(&self) -> String {
        format!("v{}", self.text)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// A number with no leading zero, as semver writes one.
fn number(text: &str) -> Option<u64> {
    let ok = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    ok.then(|| text.parse().ok()).flatten()
}

fn ident(text: &str) -> Option<Ident> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return number(text).map(Ident::Number);
    }
    Some(Ident::Text(text.to_string()))
}

impl Ord for Ident {
    fn cmp(&self, other: &Ident) -> Ordering {
        match (self, other) {
            (Ident::Number(a), Ident::Number(b)) => a.cmp(b),
            (Ident::Number(_), Ident::Text(_)) => Ordering::Less,
            (Ident::Text(_), Ident::Number(_)) => Ordering::Greater,
            (Ident::Text(a), Ident::Text(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Ident) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Version) -> Ordering {
        self.core.cmp(&other.core).then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.pre.cmp(&other.pre),
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The tag of each release in the answer of GitHub's
/// `GET /repos/OWNER/REPO/releases`, drafts left out.
pub fn tags_of_api(json: &[u8]) -> Result<Vec<String>, String> {
    let list: serde_json::Value = serde_json::from_slice(json).map_err(|e| format!("not JSON: {e}"))?;
    let list = list.as_array().ok_or("not a list of releases")?;
    Ok(list
        .iter()
        .filter(|r| !r["draft"].as_bool().unwrap_or(false))
        .filter_map(|r| r["tag_name"].as_str().map(str::to_string))
        .collect())
}

/// The tag of each entry of the feed `https://github.com/OWNER/REPO/releases.atom`:
/// the last part of its link, `.../releases/tag/TAG`.
pub fn tags_of_atom(xml: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(xml).map_err(|_| "not UTF-8")?;
    let doc = roxmltree::Document::parse(text).map_err(|e| format!("not XML: {e}"))?;
    let tags = doc
        .descendants()
        .filter(|n| n.has_tag_name("entry"))
        .filter_map(|entry| {
            let link = entry
                .children()
                .find(|n| n.has_tag_name("link") && n.attribute("rel").unwrap_or("alternate") == "alternate")?;
            let (_, tag) = link.attribute("href")?.rsplit_once("/releases/tag/")?;
            Some(tag.to_string())
        })
        .collect();
    Ok(tags)
}

/// The newest of `tags` that is a version, a prerelease only when
/// `prerelease` allows one.
pub fn newest(tags: &[String], prerelease: bool) -> Option<Version> {
    tags.iter().filter_map(|t| Version::of_tag(t)).filter(|v| prerelease || !v.is_prerelease()).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} parses"))
    }

    #[test]
    fn versions_are_ordered_as_semver_orders_them() {
        let order = [
            "0.9.0",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-beta.2",
            "1.0.0-beta.10",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.10.0",
        ];
        for pair in order.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert_eq!(v("1.0.0+abc").cmp(&v("1.0.0")), Ordering::Equal);
        for wrong in ["1.0", "1.0.0.0", "01.0.0", "1.0.0-", "1.0.0-be ta", "v1.0.0", "1.0.0-01"] {
            assert!(Version::parse(wrong).is_none(), "{wrong}");
        }
        assert_eq!(Version::of_tag("v1.0.0-beta.2").map(|v| v.tag()).as_deref(), Some("v1.0.0-beta.2"));
        assert!(Version::of_tag("1.0.0").is_none());
    }

    #[test]
    fn the_newest_is_a_prerelease_only_when_one_is_allowed() {
        let tags: Vec<String> =
            ["v1.0.0-beta.2", "v0.9.1", "v1.0.0-beta.10", "nightly", "v1.0.0-beta.9"].map(String::from).to_vec();
        assert_eq!(newest(&tags, true).map(|v| v.tag()).as_deref(), Some("v1.0.0-beta.10"));
        assert_eq!(newest(&tags, false).map(|v| v.tag()).as_deref(), Some("v0.9.1"));
        assert_eq!(newest(&tags[3..4], true), None);
    }

    #[test]
    fn the_api_s_list_gives_its_tags_without_drafts() {
        let json = br#"[{"tag_name":"v1.0.0-beta.3","draft":true},{"tag_name":"v1.0.0-beta.2","draft":false,"prerelease":true},{"tag_name":"v1.0.0-beta.1"}]"#;
        assert_eq!(tags_of_api(json).unwrap(), ["v1.0.0-beta.2", "v1.0.0-beta.1"]);
        assert!(tags_of_api(b"{\"message\":\"API rate limit exceeded\"}").is_err());
    }

    /// The form of GitHub's feed, as `https://github.com/OWNER/REPO/releases.atom`
    /// serves it.
    #[test]
    fn the_feed_gives_the_tag_of_each_entry() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:media="http://search.yahoo.com/mrss/" xml:lang="en-US">
  <id>tag:github.com,2008:https://github.com/Azathothas/podssh/releases</id>
  <link type="text/html" rel="alternate" href="https://github.com/Azathothas/podssh/releases"/>
  <title>Release notes from podssh</title>
  <entry>
    <id>tag:github.com,2008:Repository/1/v1.0.0-beta.2</id>
    <updated>2026-10-31T00:30:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.2"/>
    <title>podssh v1.0.0-beta.2</title>
    <content type="html">&lt;p&gt;notes&lt;/p&gt;</content>
  </entry>
  <entry>
    <id>tag:github.com,2008:Repository/1/v1.0.0-beta.1</id>
    <link rel="alternate" type="text/html" href="https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.1"/>
  </entry>
</feed>"#;
        assert_eq!(tags_of_atom(xml).unwrap(), ["v1.0.0-beta.2", "v1.0.0-beta.1"]);
        assert!(tags_of_atom(b"<html>a login page</html>").unwrap().is_empty());
    }
}
