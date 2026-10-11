//! An Ansible inventory in its INI form (T-047), read as Ansible's `ini`
//! inventory plugin reads it: hosts before any section are ungrouped; `[G]`
//! lists the hosts of G, each with `key=value` words; `[G:vars]` gives the
//! variables of G and `[G:children]` its child groups; `#` and `;` start a
//! comment line. A host may carry a port (`host:2222`), and a range in
//! brackets names several (`www[01:03]`, `db-[a:c]`, `n[1:9:2]`). A host's
//! variables are those of `all`, then of each of its groups by depth and
//! then by name, then its own, the later winning, as Ansible combines them.

use std::collections::BTreeMap;

/// One host, its variables combined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The name in the inventory.
    pub name: String,
    /// Its groups, as listed, in the order first met.
    pub groups: Vec<String>,
    pub vars: BTreeMap<String, String>,
}

#[derive(Default)]
struct Group {
    vars: BTreeMap<String, String>,
    parents: Vec<String>,
}

#[derive(Default)]
struct Inventory {
    /// The hosts in the order first met, each with its own variables.
    hosts: Vec<(String, BTreeMap<String, String>)>,
    /// Each host's groups, as listed.
    membership: BTreeMap<String, Vec<String>>,
    groups: BTreeMap<String, Group>,
}

/// The hosts of an inventory, in the order first met. An error names the
/// line: `LINE: why`.
pub fn read(text: &str) -> Result<Vec<Host>, String> {
    let mut inv = Inventory::default();
    inv.groups.entry("all".into()).or_default();
    // The section: a group's hosts, its variables, or its children.
    let mut section = (String::from("ungrouped"), Kind::Hosts);
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let at = |why: String| format!("{}: {why}", i + 1);
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let (name, kind) = match header.split_once(':') {
                None => (header, Kind::Hosts),
                Some((name, "vars")) => (name, Kind::Vars),
                Some((name, "children")) => (name, Kind::Children),
                Some((_, other)) => {
                    return Err(at(format!("[{header}]: a section of {other}, which Ansible does not have")))
                }
            };
            if name.is_empty() || name.contains(char::is_whitespace) {
                return Err(at(format!("[{header}]: not a group name")));
            }
            inv.groups.entry(name.to_string()).or_default();
            section = (name.to_string(), kind);
            continue;
        }
        let (group, kind) = (&section.0, section.1);
        match kind {
            Kind::Hosts => inv.host_line(line, group).map_err(at)?,
            Kind::Vars => {
                let (key, value) = line.split_once('=').ok_or_else(|| at(format!("{line}: expected key=value")))?;
                let value = unquote(value.trim());
                inv.groups.entry(group.clone()).or_default().vars.insert(key.trim().to_string(), value);
            }
            Kind::Children => {
                let child = line.split_whitespace().next().unwrap_or(line);
                let parents = &mut inv.groups.entry(child.to_string()).or_default().parents;
                if !parents.contains(group) {
                    parents.push(group.clone());
                }
            }
        }
    }
    Ok(inv.combined())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Hosts,
    Vars,
    Children,
}

impl Inventory {
    /// `PATTERN [key=value ...]`, in group `group`.
    fn host_line(&mut self, line: &str, group: &str) -> Result<(), String> {
        let words = split(line)?;
        let (pattern, rest) = words.split_first().ok_or("an empty line")?;
        let mut vars = BTreeMap::new();
        for word in rest {
            let (key, value) = word.split_once('=').ok_or_else(|| format!("{word}: expected key=value"))?;
            vars.insert(key.to_string(), value.to_string());
        }
        let (names, port) = expand(pattern)?;
        if let Some(port) = port {
            vars.entry("ansible_port".into()).or_insert(port);
        }
        for name in names {
            match self.hosts.iter_mut().find(|(n, _)| *n == name) {
                Some((_, own)) => own.extend(vars.clone()),
                None => self.hosts.push((name.clone(), vars.clone())),
            }
            let groups = self.membership.entry(name).or_default();
            if group != "ungrouped" && !groups.iter().any(|g| g == group) {
                groups.push(group.to_string());
            }
        }
        self.groups.entry(group.to_string()).or_default();
        Ok(())
    }

    /// Each group's depth: 0 for `all`, 1 for one with no parent, and one
    /// more than its deepest parent.
    fn depth(&self, name: &str, seen: &mut Vec<String>) -> usize {
        if name == "all" {
            return 0;
        }
        if seen.iter().any(|s| s == name) {
            return 1;
        }
        seen.push(name.to_string());
        let parents = self.groups.get(name).map(|g| g.parents.clone()).unwrap_or_default();
        let depth = parents.iter().map(|p| self.depth(p, seen)).max().unwrap_or(0) + 1;
        seen.pop();
        depth
    }

    /// A group and its ancestors, `all` with them.
    fn ancestors(&self, name: &str, into: &mut Vec<String>) {
        if into.iter().any(|g| g == name) {
            return;
        }
        into.push(name.to_string());
        if let Some(group) = self.groups.get(name) {
            for parent in &group.parents {
                self.ancestors(parent, into);
            }
        }
    }

    fn combined(&self) -> Vec<Host> {
        self.hosts
            .iter()
            .map(|(name, own)| {
                let groups = self.membership.get(name).cloned().unwrap_or_default();
                let mut all = vec!["all".to_string()];
                for group in groups.iter().map(String::as_str).chain(groups.is_empty().then_some("ungrouped")) {
                    self.ancestors(group, &mut all);
                }
                let mut order: Vec<(usize, String)> =
                    all.into_iter().map(|g| (self.depth(&g, &mut Vec::new()), g)).collect();
                order.sort();
                let mut vars = BTreeMap::new();
                for (_, group) in &order {
                    if let Some(g) = self.groups.get(group) {
                        vars.extend(g.vars.clone());
                    }
                }
                vars.extend(own.clone());
                Host { name: name.clone(), groups, vars }
            })
            .collect()
    }
}

/// The words of a host line, as a shell splits them: quotes keep a space,
/// and a `#` that starts a word starts a comment.
pub(super) fn split(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.get_or_insert_with(String::new).push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                word.get_or_insert_with(String::new);
            }
            (None, '#') if word.is_none() => break,
            (None, c) if c.is_whitespace() => words.extend(word.take()),
            (None, c) => word.get_or_insert_with(String::new).push(c),
        }
    }
    if quote.is_some() {
        return Err(format!("{line}: a quote is not closed"));
    }
    words.extend(word);
    Ok(words)
}

/// A value of `[G:vars]`, its quotes taken off.
fn unquote(value: &str) -> String {
    for q in ['"', '\''] {
        if let Some(inner) = value.strip_prefix(q).and_then(|v| v.strip_suffix(q)) {
            return inner.to_string();
        }
    }
    value.to_string()
}

/// The names that a host pattern gives, and its port: `host:PORT`, and a
/// range in brackets, `[01:03]`, `[a:c]` or `[1:9:2]`, which may repeat.
fn expand(pattern: &str) -> Result<(Vec<String>, Option<String>), String> {
    // A port: after the last `:`, outside brackets, where one `:` alone is
    // outside them (an IPv6 address has more).
    let (pattern, port) = match pattern.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && outside(pattern) == 1 => {
            (host, Some(port.to_string()))
        }
        _ => (pattern, None),
    };
    let Some(open) = pattern.find('[') else { return Ok((vec![pattern.to_string()], port)) };
    let close = pattern[open..].find(']').map(|c| open + c).ok_or_else(|| format!("{pattern}: a [ is not closed"))?;
    let (head, range, tail) = (&pattern[..open], &pattern[open + 1..close], &pattern[close + 1..]);
    let parts: Vec<&str> = range.split(':').collect();
    let (from, to, step) = match parts.as_slice() {
        [from, to] => (*from, *to, 1),
        [from, to, step] => (*from, *to, step.parse::<usize>().ok().filter(|s| *s > 0).ok_or("not a step")?),
        _ => return Err(format!("{pattern}: a range is [FROM:TO] or [FROM:TO:STEP]")),
    };
    let mut values = Vec::new();
    if let (Ok(a), Ok(b)) = (from.parse::<usize>(), to.parse::<usize>()) {
        // A leading zero keeps the width, as Ansible keeps it.
        let width = if from.starts_with('0') { from.len() } else { 0 };
        values.extend((a..=b).step_by(step).map(|n| format!("{n:0width$}")));
    } else if let ([a], [b]) = (from.as_bytes(), to.as_bytes()) {
        values.extend((*a..=*b).step_by(step).map(|c| (c as char).to_string()));
    } else {
        return Err(format!("{pattern}: {range} is not a range of numbers or of letters"));
    }
    if values.is_empty() {
        return Err(format!("{pattern}: the range {range} names no host"));
    }
    let mut names = Vec::new();
    for value in values {
        let (more, _) = expand(&format!("{head}{value}{tail}"))?;
        names.extend(more);
    }
    Ok((names, port))
}

/// The `:` of a pattern outside its brackets.
fn outside(pattern: &str) -> usize {
    let mut depth = 0i32;
    pattern
        .chars()
        .filter(|c| {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            }
            *c == ':' && depth == 0
        })
        .count()
}

#[cfg(test)]
#[path = "ansible_tests.rs"]
mod tests;
