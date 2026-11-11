---
name: shortcuts-authoring
description: Write, build, sign, deliver and audit an Apple Shortcut with Talaria. File shape, verified action signatures, house patterns, and the rules that keep a build from silently breaking.
---

# Writing Cherri for Talaria

You write the source. `talaria_build` compiles it, `talaria_sign` signs it,
`talaria_inspect` audits it. Never hand the user a `.shortcut` you have not
compiled and inspected.

## Order of operations

1. `talaria_status()` in a new environment. If `compiler.present` is false, tell the user what
   the download is, then `talaria_setup(confirm=true)`. It installs the pinned compiler once.
2. `talaria_actions(query=...)` when unsure of an action name or argument order. Never invent one.
3. Write the source (shape below).
4. `talaria_build(source=..., name="kebab-name")` gives an unsigned `.shortcut`, the action
   inventory and a sha256.
5. `talaria_inspect(path=...)` gives the action list and the risk findings. Fix what it flags,
   or tell the user plainly what the shortcut reads, writes and sends.
6. `talaria_sign(artifact_id=..., consent=true)` only after the user agrees to the upload.
   An unsigned shortcut cannot be imported on an iPhone.
7. Hand over the file: copy `deliver.media_tag` from the sign result onto its own line of your
   reply, outside any code block. `talaria_library(action="deliver", artifact_id=...)` returns
   the same line for a stored artifact.
8. Say how to install it: open the file on the iPhone, choose Shortcuts, tap Add Shortcut.
   Report the inventory and the findings too, not just "done".

## Auditing a shortcut someone shared

`talaria_inspect(url="https://www.icloud.com/shortcuts/<id>")` downloads the file from Apple and
audits it. `talaria_inspect(path=...)` does the same for a file on disk. Nothing is installed or
run. Report every finding with its severity and the verdict as given: `dangerous` (a high
finding), `review` (a medium or low finding, or an action Talaria has no rule for) or
`no-findings`. Never restate `review` or `no-findings` as "safe".

## File shape

```ruby
// One-line intent, then includes, then the body.
#include 'actions/calendar'     // only for families outside basic
#include 'actions/documents'

const now = currentDate()
const stamp = formatDate(now, "Custom", "yyyy-MM-dd HH:mm")
@line = "note at {stamp}"        // @var is mutable; a string interpolates it

if !@line {
  alert("Nothing to save", "Talaria")
} else {
  saveFile("talaria/notes.txt", @line, true)
  show("Saved")
}
```

- `#include 'actions/<family>'` once, at column 1. Basic actions need no include.
  Families: calendar, documents, text, web, sharing, shortcuts, contacts, images,
  photos, location, device, network, crypto, pdf, media, music, settings, math.
- Constants `const x = ...` have no `@`; variables `@x = ...` do, including inside
  strings: `"{@x}"` and `"{x}"`.
- `#define` lines (`glyph`, `color`, `inputs`, `outputs`, `noinput`) must start at
  column 1 with exactly one space: `#define glyph smileyFace`.
- Output: `show(x)`, `output(x)`, `stop()`.

## Verified actions (compile rc=0, signatures quoted from the compiler)

```
alert(text alert, text ?title)
confirm(text alert, text ?title)
show(text input)
prompt(text prompt, inputType ?inputType = "Text", text ?defaultValue, text ?multiline = true)
showNotification(text body, text ?title, bool ?playSound = true, variable ?attachment)
openURL(text url)                                     # web
downloadURL(text url, dictionary! ?headers): variable # web, GET
jsonRequest(text url, HTTPMethod ?method, dictionary! ?body, dictionary! ?headers)  # web
formRequest(text url, HTTPMethod ?method, dictionary! ?body, dictionary! ?headers)  # web
getValue(dictionary dictionary, text key): variable
getClipboard()                                        # sharing
setClipboard(variable value, bool ?local = false, text ?expire)   # sharing
saveFile(text path, &variable content, bool ?overwrite = false)   # documents
currentDate(): date                                   # calendar
formatDate(text date, dateFormats ?dateFormat = "Short", text ?customDateFormat): text  # calendar
chooseFromList(variable list, text ?prompt, bool ?selectMultiple = false, bool ?selectAll = false)
run(text shortcutName, variable input)                # shortcuts
speak(text prompt, bool ?waitUntilFinished = true, text ?language) # text
hash(variable input, hashType ?type = "MD5"): text    # crypto
base64Encode(variable encodeInput): text              # crypto
wait(number seconds)
```

Enums: `inputType` Text, Number, URL, Date, Time, Date and Time. `dateFormats`
None, Short, Medium, Long, Relative, RFC 2822, ISO 8601, Custom. `hashType`
MD5, SHA1, SHA256, SHA512. A wrong value prints the valid list in the error.

## House patterns

Alert / confirm:

```ruby
alert("Backup finished", "Talaria")
if !confirm("Delete the draft?", "Talaria") { stop() }
```

Ask for input:

```ruby
const answer = prompt("How many?", "Number", "3")
const who = prompt("Who?", "Text", "Mike")
```

Open a URL, or POST JSON:

```ruby
#include 'actions/web'
openURL("https://example.com/report")

#include 'actions/web'
#include 'actions/sharing'
const clip = getClipboard()
const reply = jsonRequest("https://example.com/collect", "POST", {"c": "{clip}"})
show("{reply}")
```

Conditional (empty test is `!var`, never `== ""`):

```ruby
if !body {
  alert("Empty note discarded", "Talaria")
} else {
  saveFile("talaria/notes.txt", @body, true)
}
```

Nested if instead of `else if`:

```ruby
if @n > 10 {
  show("big")
} else {
  if @n > 5 {
    show("medium")
  } else {
    show("small")
  }
}
```

Repeat and for-each:

```ruby
repeat i for 3 {
  show("pass {@i}")
}
for fruit in @fruits {
  show("{@fruit}")
}
```

Menu:

```ruby
menu "Pick one" {
  item "Tea":
    show("tea")
  item "Coffee":
    show("coffee")
}
```

## Rules that cost builds

- **Empty test:** `if !body { }`. `if body == ""` is a compile error:
  `Invalid type '' for conditional '=='`.
- **Dictionary arguments must be inline literals:** `jsonRequest(url, "POST", {"c": "{clip}"})`.
  Never assign a dict to a variable and pass it (`Shortcuts does not allow variable
  values for this argument, use a literal`), and never pass a bare identifier inside
  one — interpolate as a string: `{"c": "{clip}"}`.
- **A `variable`-typed parameter rejects literals** (`setClipboard`, `run`, `share`,
  `hash`, `base64Encode`, `number`). Put the literal in a variable first:
  `@t = "text"` then `setClipboard(@t)`.
- **Never write `else if`.** It compiles but emits unbalanced blocks. Nest an `if`
  inside `else`.
- **Leave a blank line after an `action '...' name(...)` definition**, or the next
  line is silently swallowed.
- **`rawAction(...)` is statement-only.** `const x = rawAction(...)` compiles but
  emits the wrong identifier. Define the action instead and call it.
- **Assume no `--derive-uuids`.** Never ask for it; it gives every block the same
  grouping id and breaks shortcuts with two or more blocks.
- **Compile is not proof.** `rc=0` hides broken sources; trust the inventory and
  the sha256 that `talaria_build` returns, and inspect before installing.

## Signing and installing

- `talaria_build` never signs. On Linux, compiling without `--skip-sign` uploads
  the shortcut to RoutineHub HubSign; Talaria always passes it.
- `talaria_sign` needs `consent=true` in the same call and uploads the compiled shortcut
  (every action, text field and URL in it) to the signing service. Ask the user first and
  say what leaves the machine. Never put a secret in a shortcut you are going to sign.
- Always `talaria_inspect` the final file, including a signed one, before the user
  installs it. Report every finding with its severity; do not summarise "safe".
- An unsigned `.shortcut` is a plain XML plist; a signed one is an AEA1 container
  with an LZFSE body. Inspect works on both; do not hand-decode a signed file.
