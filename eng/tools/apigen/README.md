# apigen

apigen describes a Go module's public API in a declaration-only Markdown report for architectural review.

## Usage

Run from this directory, supplying the directory containing the target module's `go.mod`:

```powershell
go run . ..\..\..\sdk\azcore
go run . ..\..\..\sdk\azcore --output ..\..\..\sdk\azcore\api.md
```

The report goes to stdout by default; `--output -` explicitly selects stdout. Use `--output` or `-o` to save a file. Output paths are relative to the current working directory, and the parent directory must already exist.

File output uses a temporary file in the destination directory and replaces the destination only after successful generation and close. Existing regular-file permissions are preserved; symlinks and other non-regular destinations are rejected. Errors go to stderr with a nonzero exit status. Ctrl+C cancels module loading.

The tool uses the current Go environment and build constraints. Use `go run . --help` for command-line help.

## Report format

- Each package has a Go code block containing its exported declarations. Its import block includes only packages referenced by public variable declarations, constant types, field types, parameters, results, embedded types, alias targets, and generic constraints, including those in expanded internal aliases. Implementation-only imports are omitted. Referenced types from other public packages are not expanded.
- Standalone functions appear first, alphabetically. Types follow alphabetically, with associated constants, variables, factory functions, and methods next to their types. Each associated group is ordered alphabetically. Unassociated constants and variables remain at package level.
- Struct fields retain their declaration order, types, tags, and embedding. Embedded types are shown by name rather than expanding their promoted members.
- Constants retain their types and evaluated values, so `iota` and references to unexported constants do not depend on omitted declarations or source ordering.
- Signatures retain type parameters, constraints, and parameter and result names. Method receivers retain their types, including pointer or value distinctions, but omit receiver variable names to avoid diff noise.
- Variables retain any explicit type annotations and initializers, as displayed by pkg.go.dev. Independently initialized names are listed separately. Shared multi-result initializers retain their binding order, with unexported names replaced by `_`.
- Aliases to internal types are expanded under their public names, including exported fields and methods. An `Alias of` comment records the target's full package path and type name; the expanded declaration is review notation, not a new defined type.
- References to internal types in expanded declarations use public aliases when available: names in this package are unqualified, and names in other packages are qualified. When no public alias exists, the actual internal type reference is retained. Aliases to public types retain their `type Name = package.Type` declarations.
- Implementation bodies, unexported declarations, and descriptive comments are omitted. A `Contains no exported fields` comment marks structs containing only unexported fields; it is omitted when a struct also has exported fields.
- The module section groups the module path, Go version, and a filtered `require` block using `go.mod` syntax. Requirements are deduplicated and sorted by module path, with their selected versions.
- The `require` block includes only external modules imported directly by non-test code anywhere in the module, including internal packages. Standard library imports, imports within this module, test-only dependencies, and dependencies used only transitively are excluded. Direct, non-test usage is determined from source imports, not solely from `go.mod` requirements or `// indirect` annotations.

## Alias normalization

When multiple public aliases identify the same internal type, references prefer an alias in the current package, then the first alias ordered by import path and name. An expanded type's self-references use its own public name.

Generic internal aliases and instantiated internal targets currently produce an explicit error. Unaliased internal types referenced by expanded declarations are preserved, including generic type references. Expansion fails when rebinding an embedded type would change its field name.

## Import collection

Imports are collected from displayed declarations, including variable initializers and evaluated constant types. Source aliases and dot imports are preserved; imports used only in omitted declarations, fields, function bodies, or constant expressions are excluded.

When separate source files use the same qualifier for different packages, collection currently returns an explicit error rather than emitting a conflicting import block.

## Declaration grouping

Methods belong to their public receiver type. Constants belong to their named type; variable declarations belong to a type when all exported bindings refer to the same local type. Pointer indirection does not change the association.

Functions belong to a type when exactly one result refers to a local named type, including through pointers, slices, or arrays. Other functions remain at package level. Generic types are matched by declaration identity, not by their type-parameter names.

An explicitly referenced public alias takes precedence over its target. When only an internal target's identity is available, the first matching local alias in alphabetical order is used.

## Markdown rendering

The renderer writes module metadata followed by package sections. The root section uses its package name; subpackage headings use module-relative paths so packages such as `policy` and `arm/policy` remain distinct. Without a root package, the report title uses the module path's final component, excluding its major-version suffix.

Package-level functions, constants, and variables precede named types. Each type is followed by its associated constants, variables, factory functions, and methods. Multiple constants or variable declarations in one group use a parenthesized block.

Go declarations are formatted consistently, without blank lines inherited from omitted source comments or fields. Multiline literal contents are preserved. Numeric constants use exact Go expressions rather than approximate display values.

An absent Go directive or empty dependency list is omitted from the module block. A dependency without a selected version is an error. The complete document is rendered before output begins, so rendering failures do not leave partial reports; output errors are returned to the caller.
