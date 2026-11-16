# Wallet-Session Roadmap

This table has a list of all the features we'd like. Each top-level item links to a markdown file
which has a detailed description of the feature and its sub-feature.

Before working on a nontrivial feature, please make sure that it has a document in this tree. 

## Taking Work

While working on a feature, try to keep the `Status` and `PRs` column in this table up to date:

* When a feature is first suggested, throw it in the table with status `Needs design`.
* Once it has a design document, change this to `Proposed`.
* Once it is in progress, change it to `In progress` and then `Completed`.

To take on a feature, first make sure that it has an entry in the table and appears in a
linked design document. Each design document should have an owner listed. (If there is no
owner, please volunteer or ask somebody to take this on.) **The owner's responsibility is
to respond to complaints when things are stalled or blocked.** The owner doesn't necessarily
need write or review code (unless this is blocking progress) or even maintain the design
document; they are just the central point-of-contact for the feature.

Once the feature has a document, go ahead and just open PRs against the repo as you normally
would. (If there are controversial high-level design considerations in your PR, you may need
to first PR to update the design document, but ideally this won't happen too much because
we don't want process friction when implementing stuff we've agreed to do.)

## Current Priorities

This section gives an idea of what we are working on. We should endeavor to update at least once
per quarter.

Our highest priorities right now (Q4 2026) are:

* the outstanding client review findings `WSC-1`
* the generalized client API `WSC-2`
* the high-level async API `WSC-5`, designed alongside `WSC-2`

WASM and UniFFI support follow once the generalized API is stable.

# All Features

Feel free to add any feature to this list, no matter how futuristic or
low-priority. Its purpose is to define the DAG of dependencies so that we can
understand what is blocking the high-priority items.

| ID     | Name                 | Description                                                                                          | Dependencies  | Status       | PRs |
|--------|----------------------|------------------------------------------------------------------------------------------------------|---------------|--------------|-----|
| WSC    | [Wallet Session Client](WSC.md) | Client crate as a library to communicate with the Relay                                    | -             | -            | -   |
| WSC-1  | Review findings      | Address all client review findings                                     | -             | In progress  | #14 |
| WSC-2  | Generalized core     | Expose high-level client functions as a library API so application protocols can be built on top     | WSC-1         | Needs design | -   |
| WSC-3  | WASM support         | Verify wasm-bindgen exposure, dependency support and a `wasm32-unknown-unknown` build                | WSC-2, WSC-5  | Needs design | -   |
| WSC-4  | Bindings support     | Verify UniFFI bindings for the client, on the same API surface as WASM                               | WSC-2, WSC-5  | Needs design | -   |
| WSC-5  | Async API            | High-level async API spec, applied wherever it fits best without prescribing implementation details   | WSC-1         | Needs design | -   |
