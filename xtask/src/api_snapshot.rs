use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// API snapshot input and output paths.
#[derive(Debug, Clone)]
pub struct ApiSnapshotRequest {
    /// Rustdoc JSON generated for `wc-core`.
    pub rustdoc_json: PathBuf,
    /// Checked-in snapshot path.
    pub output: PathBuf,
}

/// Prints the generated snapshot to stdout.
pub fn print(request: &ApiSnapshotRequest) -> Result<()> {
    print!("{}", generate(request)?);
    Ok(())
}

/// Writes the generated snapshot to disk.
pub fn update(request: &ApiSnapshotRequest) -> Result<()> {
    let snapshot = generate(request)?;
    if let Some(parent) = request.output.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create API snapshot directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(&request.output, snapshot)
        .with_context(|| format!("failed to write API snapshot {}", request.output.display()))
}

/// Verifies that the checked-in snapshot matches the generated snapshot.
pub fn check(request: &ApiSnapshotRequest) -> Result<()> {
    let expected = fs::read_to_string(&request.output)
        .with_context(|| format!("failed to read API snapshot {}", request.output.display()))?;
    let actual = generate(request)?;
    if expected == actual {
        println!("api-snapshot ok {}", request.output.display());
        return Ok(());
    }

    bail!(
        "API snapshot is stale: run `just api_snapshot_update` and review {}",
        request.output.display()
    );
}

fn generate(request: &ApiSnapshotRequest) -> Result<String> {
    let document = RustdocDocument::read(&request.rustdoc_json)?;
    let mut entries = Vec::new();
    document.collect_module(document.root_id(), "wc_core", &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path).then(left.kind.cmp(right.kind)));

    let mut output = String::new();
    output.push_str("# wc-core public API snapshot\n");
    output.push_str("# Generated from rustdoc JSON with wc-core --all-features.\n");
    output.push_str("# Update with: just api_snapshot_update\n\n");
    output.push_str("crate wc_core ");
    output.push_str(document.crate_version());
    output.push('\n');

    for entry in entries {
        output.push('\n');
        output.push_str(entry.kind);
        output.push(' ');
        output.push_str(&entry.path);
        output.push('\n');

        for detail in document.item_details(entry.id)? {
            output.push_str("  ");
            output.push_str(&detail);
            output.push('\n');
        }
    }

    Ok(output)
}

#[derive(Debug)]
struct ApiEntry {
    kind: &'static str,
    path: String,
    id: u64,
}

struct RustdocDocument {
    root: u64,
    crate_version: String,
    index: HashMap<u64, Value>,
    paths: HashMap<u64, Value>,
}

impl RustdocDocument {
    fn read(path: &PathBuf) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read rustdoc JSON {}", path.display()))?;
        let root: Value =
            serde_json::from_str(&raw).context("failed to parse rustdoc JSON document")?;
        let root_id = root
            .get("root")
            .and_then(Value::as_u64)
            .context("rustdoc JSON missing root id")?;
        let crate_version = root
            .get("crate_version")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let index = root
            .get("index")
            .and_then(Value::as_object)
            .context("rustdoc JSON missing index")?
            .iter()
            .filter_map(|(id, item)| id.parse::<u64>().ok().map(|id| (id, item.clone())))
            .collect();
        let paths = root
            .get("paths")
            .and_then(Value::as_object)
            .context("rustdoc JSON missing paths")?
            .iter()
            .filter_map(|(id, item)| id.parse::<u64>().ok().map(|id| (id, item.clone())))
            .collect();

        Ok(Self {
            root: root_id,
            crate_version,
            index,
            paths,
        })
    }

    const fn root_id(&self) -> u64 {
        self.root
    }

    fn crate_version(&self) -> &str {
        &self.crate_version
    }

    fn collect_module(
        &self,
        module_id: u64,
        module_path: &str,
        entries: &mut Vec<ApiEntry>,
    ) -> Result<()> {
        let item = self.item(module_id)?;
        for child_id in module_items(item)? {
            let child = self.item(child_id)?;
            if !is_public_item(child) {
                continue;
            }

            match inner_kind(child)? {
                "module" => {
                    let name = child
                        .get("name")
                        .and_then(Value::as_str)
                        .context("public module missing name")?;
                    let path = format!("{module_path}::{name}");
                    entries.push(ApiEntry {
                        kind: "mod",
                        path: path.clone(),
                        id: child_id,
                    });
                    self.collect_module(child_id, &path, entries)?;
                }
                "use" => {
                    let use_item = child
                        .pointer("/inner/use")
                        .context("use item missing inner payload")?;
                    let is_glob = use_item
                        .get("is_glob")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if is_glob {
                        if let Some(target_id) = use_item.get("id").and_then(Value::as_u64) {
                            if self
                                .index
                                .get(&target_id)
                                .is_some_and(|target| inner_kind(target).ok() == Some("module"))
                            {
                                self.collect_module(target_id, module_path, entries)?;
                            }
                        }
                        continue;
                    }
                    let Some(target_id) = use_item.get("id").and_then(Value::as_u64) else {
                        continue;
                    };
                    let Some(kind) = self.api_kind_for_id(target_id) else {
                        continue;
                    };
                    let name = use_item
                        .get("name")
                        .and_then(Value::as_str)
                        .context("use item missing exported name")?;
                    entries.push(ApiEntry {
                        kind,
                        path: format!("{module_path}::{name}"),
                        id: target_id,
                    });
                }
                _ => {
                    let Some(kind) = api_kind(child) else {
                        continue;
                    };
                    let Some(name) = child.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    entries.push(ApiEntry {
                        kind,
                        path: format!("{module_path}::{name}"),
                        id: child_id,
                    });
                }
            }
        }

        Ok(())
    }

    fn item_details(&self, item_id: u64) -> Result<Vec<String>> {
        let Some(item) = self.index.get(&item_id) else {
            return Ok(Vec::new());
        };
        match inner_kind(item)? {
            "struct" => self.associated_functions(item),
            "enum" => {
                let mut details = enum_variants(item, self)?;
                details.extend(self.associated_functions(item)?);
                Ok(details)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn associated_functions(&self, item: &Value) -> Result<Vec<String>> {
        let mut names = BTreeSet::new();
        for impl_id in item_impls(item)? {
            let impl_item = self.item(impl_id)?;
            let Some(impl_body) = impl_item.pointer("/inner/impl") else {
                continue;
            };
            if !impl_body.get("trait").is_some_and(Value::is_null) {
                continue;
            }

            let Some(items) = impl_body.get("items").and_then(Value::as_array) else {
                continue;
            };
            for function_id in items.iter().filter_map(Value::as_u64) {
                let function = self.item(function_id)?;
                if !is_public_item(function) || inner_kind(function)? != "function" {
                    continue;
                }

                let name = function
                    .get("name")
                    .and_then(Value::as_str)
                    .context("function item missing name")?;
                let header = function
                    .pointer("/inner/function/header")
                    .context("function missing header")?;
                let mut detail = String::new();
                if header
                    .get("is_const")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    detail.push_str("const ");
                }
                if header
                    .get("is_async")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    detail.push_str("async ");
                }
                detail.push_str("fn ");
                detail.push_str(name);
                names.insert(detail);
            }
        }

        Ok(names.into_iter().collect())
    }

    fn item(&self, id: u64) -> Result<&Value> {
        self.index
            .get(&id)
            .with_context(|| format!("rustdoc JSON item {id} missing"))
    }

    fn api_kind_for_id(&self, id: u64) -> Option<&'static str> {
        if let Some(item) = self.index.get(&id) {
            return api_kind(item);
        }

        match self.paths.get(&id)?.get("kind")?.as_str()? {
            "constant" => Some("const"),
            "enum" => Some("enum"),
            "function" => Some("fn"),
            "module" => Some("mod"),
            "struct" => Some("struct"),
            "type_alias" => Some("type"),
            "trait" => Some("trait"),
            _ => None,
        }
    }
}

fn enum_variants(item: &Value, document: &RustdocDocument) -> Result<Vec<String>> {
    let mut variants = Vec::new();
    for variant_id in item
        .pointer("/inner/enum/variants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
    {
        let variant = document.item(variant_id)?;
        let Some(name) = variant.get("name").and_then(Value::as_str) else {
            continue;
        };
        variants.push(format!("variant {name}"));
    }
    Ok(variants)
}

fn item_impls(item: &Value) -> Result<Vec<u64>> {
    let kind = inner_kind(item)?;
    Ok(item
        .pointer(&format!("/inner/{kind}/impls"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect())
}

fn module_items(item: &Value) -> Result<Vec<u64>> {
    Ok(item
        .pointer("/inner/module/items")
        .and_then(Value::as_array)
        .context("module item missing children")?
        .iter()
        .filter_map(Value::as_u64)
        .collect())
}

fn api_kind(item: &Value) -> Option<&'static str> {
    match inner_kind(item).ok()? {
        "constant" => Some("const"),
        "enum" => Some("enum"),
        "function" => Some("fn"),
        "module" => Some("mod"),
        "struct" => Some("struct"),
        "type_alias" => Some("type"),
        "trait" => Some("trait"),
        _ => None,
    }
}

fn inner_kind(item: &Value) -> Result<&str> {
    item.get("inner")
        .and_then(Value::as_object)
        .and_then(|inner| inner.keys().next())
        .map(String::as_str)
        .context("rustdoc item missing inner kind")
}

fn is_public_item(item: &Value) -> bool {
    matches!(
        item.get("visibility").and_then(Value::as_str),
        Some("public")
    )
}
