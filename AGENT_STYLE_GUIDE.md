# Magnetar Agent Commenting & Function Style Guide

This document defines the tone, structure, and wording expected from generated comments and function bodies so the output reads like it was written by the repo author rather than a generic AI assistant.

The goal is not to be verbose. The goal is to be direct, technical, and practical.

## Core principle

Write like a maintainer who cares about correctness, not a tutorial writer.

Good comments sound like operational notes:
- brief
- factual
- action-oriented
- specific to the code path
- written in the present tense when describing a state or action

Avoid:
- generic explanations
- marketing language
- scaffolding that explains what a language feature is
- fluffy narration
- repeated “This function does…” comments
- AI phrasing like “we can,” “let’s,” “in order to,” “it is worth noting,” etc.

---

## Comment style

### 1) Comments should describe the action, not the concept

Use comments that explain the intent of the block in a practical way:

```c
// Allocate memory for shellcode in target process...
```

```js
// Create the process in suspended state before injection.
```

```html
<!-- Main layout container -->
```

```css
/* Layout block: app shell */
```

Do not write:

```c
// This function allocates memory in the target process for the shellcode payload.
```

```js
// This section handles the process of creating the suspended process before injection begins.
```

The first version is better because it reads like a note from the code author. The second is explanatory and AI-like.

### 2) Keep comments terse and real

Good comments are usually one short line or a short block of 2-3 lines max.

Use:
- action verbs
- exact nouns
- failure states when useful
- explicit status words

Examples:

```c
// Failed to patch ETW, continuing with higher detection risk
```

```c
// Using execution delay of %d minutes
```

```js
// Guard against empty input before continuing.
```

### 3) Prefer surgical comments over explanatory comments

Only add a comment when it clarifies a non-obvious decision, cleanup step, workaround, or failure path.

Good places for comments:
- guard conditions
- unusual memory or process logic
- syscall or OS API edge cases
- cleanup after failure
- security / debugging workarounds

Avoid comments on obvious code:

```c
int x = 0; // initialize x
```

```js
const value = 1; // set value to 1
```

That is noise.

### 4) Match the repo’s log/diagnostic tone

The project uses terse operational logging patterns such as:

```c
okay("Found accessible %ls process with primary method", gProcName);
warn("Failed to patch ETW, continuing with higher detection risk");
fail("CreateProcess failed with error: %d", GetLastError());
info("Allocating memory for shellcode in target process...");
```

This style should be mirrored in generated comments and log messages:

- `okay(...)` for success
- `info(...)` for progress
- `warn(...)` for degraded state
- `fail(...)` for hard errors

The wording should feel practical, not cheerful or verbose.

---

## Function-writing style

### 1) One job per function

Each function should do one narrow task.

Good structure:
- validate arguments early
- fail fast if state is invalid
- do the work
- return a clear success/error result
- clean up on failure

Example:

```c
static BOOL setup_ppid_spoofing(void *startup_info_ex, LPCWSTR spoof_proc_name, BOOL is_wide)
{
    DWORD PID_spoof = 0;
    HANDLE hProcess_spoof = NULL;

    if (!spoof_proc_name)
    {
        fail("Spoof process name is null");
        return FALSE;
    }

    pr_enum(spoof_proc_name, &PID_spoof, &hProcess_spoof);
    if (!hProcess_spoof)
    {
        fail("Failed to find spoof process");
        return FALSE;
    }

    // duplicate handle for inheritance
    if (!DuplicateHandle(...))
    {
        fail("Failed to duplicate handle for inheritance");
        CloseHandle(hProcess_spoof);
        return FALSE;
    }

    return TRUE;
}
```

This is the preferred style: explicit guard clauses, direct status checks, and cleanup before exit.

### 2) Keep function names descriptive and technical

Use names that reflect what the function is doing, not abstract business language.

Good:
- `protect_process`
- `setup_ppid_spoofing`
- `populate_table`
- `select_method`
- `ExecDelay`

Avoid:
- `doStuff`
- `handleThing`
- `runLogic`
- `processRequest`
- `prepareValue`

### 3) Return early on failure

Do not let a function continue after a failed precondition.

Prefer:

```c
if (!valid_input)
{
    warn("Invalid input, exiting");
    return FALSE;
}
```

over:

```c
if (!valid_input)
{
    // continue anyway and see what happens
}
```

The repo is strongly defensive and explicit. Do not hide failure paths.

### 4) Use clear failure messages

A function should make its failure obvious.

Good:
- `fail("CreateProcess failed with error: %d", GetLastError());`
- `warn("Failed to protect process, continuing without process protection!");`
- `info("Allocating memory for shellcode in target process...");`

Avoid vague wording:
- `error occurred`
- `something broke`
- `failed unexpectedly`
- `could not complete operation`

### 5) Keep state transitions obvious

When a function changes state or process security, say so plainly.

Examples:

```c
okay("Changed process security descriptor.");
info("Creating process in suspended state...");
okay("Thread resumed successfully");
```

This is a direct, maintainable pattern.

---

## Wording rules for generated output

### Prefer these patterns

- `Create process in suspended state...`
- `Failed to protect process...`
- `Found accessible process...`
- `Setting up PPID spoofing...`
- `Allocating memory for shellcode...`
- `Queueing APC to execute shellcode...`
- `Changed process security descriptor.`

### Avoid these patterns

- `This function is used to...`
- `In order to achieve...`
- `The purpose of this section is...`
- `We can now proceed to...`
- `It is important to note that...`
- `As you may know...`
- `This is a high-level overview...`
- `Very nice and efficient solution...`

The repo does not speak in tutorials. It speaks in execution notes.

---

## Cross-language adaptation

These rules should apply across C, JS, HTML, and CSS.

### C

Use short comments before important blocks and concise error logs.

```c
// Setup PPID spoofing for the target process.
if (!setup_ppid_spoofing(...))
{
    fail("PPID spoofing failed");
    return -1;
}
```

### JavaScript

Use short comments and explicit early returns.

```js
// Guard against empty input before continuing.
if (!value) {
  console.warn('Invalid input');
  return;
}
```

Do not use chatty comments like “this is used to validate the input before continuing.”

### HTML

Use minimal section markers.

```html
<!-- Main shell layout -->
<div class="app-shell">
  ...
</div>
```

Avoid long narrative comments inside markup.

### CSS

Use concise section comments only when a block is non-obvious.

```css
/* Layout: app shell */
.app-shell {
  display: grid;
}
```

Do not write essay comments like “This section styles the main application shell to ensure layout stability across browsers.”

---

## Example of the desired tone

Good:

```c
// Create process in suspended state before injection.
if (!CreateProcessW(...))
{
    fail("CreateProcess failed with error: %d", GetLastError());
    return -1;
}
```

```js
// Protect the target object before mutation.
if (!protectTarget(target)) {
  console.warn('Protection failed, continuing with reduced safeguards');
}
```

```html
<!-- Target process panel -->
<section class="process-panel"></section>
```

```css
/* Process view layout */
.process-panel {
  position: relative;
}
```

Bad:

```c
// This block creates the process and sets it to suspended state to allow injection.
```

```js
// This function protects the target object before mutation because it is required for safety.
```

```html
<!-- This section contains the target process panel for the UI -->
```

```css
/* This block styles the process panel to make the interface more readable */
```

---

## Final rule

When generating comments or function bodies, write as if you are leaving operational notes in a codebase for the next engineer, not writing documentation for a blog post.

The output should feel:
- sharp
- direct
- practical
- compact
- technical
- slightly terse

The default voice is not “AI-helpful.” The default voice is “maintainer notes.”

That is the style to emulate.
