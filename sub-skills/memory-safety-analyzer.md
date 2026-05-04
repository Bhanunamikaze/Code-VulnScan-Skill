# memory-safety-analyzer

Read this when the codebase includes C, C++, or unsafe Rust code.

## Goal

Find memory corruption vulnerabilities: buffer overflows, use-after-free, format string vulnerabilities, integer overflows in size calculations, and null pointer dereferences — focusing on those reachable from user-controlled input.

## Scope

Skip this sub-skill entirely for pure Python, JavaScript, Java, Go, Ruby, or C# codebases with no native extensions. Apply it to:
- C and C++ source files (`.c`, `.cpp`, `.h`, `.hpp`, `.cc`, `.cxx`)
- Rust files with `unsafe {}` blocks
- Python/Ruby/Node.js extensions in C (`.c` files with Python/Ruby C API calls)
- Any code that interfaces with native libraries via FFI

## Part 1: Buffer overflows

### Stack buffer overflow

Flag any fixed-size buffer receiving user-controlled data without length checking:

```c
// Flag: unbounded copy into fixed buffer
char buf[256];
gets(buf);                          // critical: no bounds check at all
scanf("%s", buf);                   // critical: no width limit
strcpy(buf, user_input);            // critical: no bounds check
strcat(buf, user_input);            // critical: no bounds check
sprintf(buf, "%s %s", s1, s2);     // critical: no length check

// Safer
fgets(buf, sizeof(buf), stdin);
snprintf(buf, sizeof(buf), "%s %s", s1, s2);
strncpy(buf, src, sizeof(buf) - 1);
strncat(buf, src, sizeof(buf) - strlen(buf) - 1);
```

### Heap buffer overflow

```c
// Flag: allocation size not accounting for all data
char *buf = malloc(strlen(src));     // off-by-one: missing +1 for null terminator
memcpy(buf, src, user_len);         // user_len not validated against buf size
buf[user_idx] = value;              // user_idx not bounds-checked

// Flag: integer overflow in allocation size
size_t total = count * element_size;  // overflows if count is large
char *buf = malloc(count * size);     // same
// Safe: check for overflow before multiplication
if (count > SIZE_MAX / element_size) { handle_error(); }
```

### Off-by-one errors

```c
// Flag: <= instead of < in loop bound
for (i = 0; i <= bufsize; i++) {   // writes one past end
    buf[i] = data[i];
}

// Flag: null terminator placement
strncpy(dst, src, sizeof(dst));    // does NOT guarantee null termination
// Safe: dst[sizeof(dst)-1] = '\0'; after strncpy
```

## Part 2: Use-after-free and dangling pointers

```c
// Flag: use after free
free(ptr);
*ptr = value;           // use-after-free
ptr->field = value;     // use-after-free
func(ptr);              // use-after-free

// Flag: double free
free(ptr);
free(ptr);              // double free — heap corruption

// Flag: dangling pointer returned
int *foo() {
    int local = 42;
    return &local;      // stack variable goes out of scope
}

// Flag: pointer used after realloc of same pointer
ptr = realloc(ptr, new_size);   // original ptr is now invalid
// Old code still using the pre-realloc value via another alias
```

## Part 3: Format string vulnerabilities

A format string vulnerability occurs when user input is passed as the format argument to `printf`-family functions.

```c
// Critical: user input as format string
printf(user_input);                 // can read/write memory, leak addresses
fprintf(stderr, user_input);
sprintf(buf, user_input);
syslog(LOG_INFO, user_input);

// Safe: always use a format string literal
printf("%s", user_input);
fprintf(stderr, "%s", user_input);
syslog(LOG_INFO, "%s", user_input);
```

Also flag:
```python
# Python — % formatting with user-controlled format
"%s" % user_input            # safe (format literal)
user_input % safe_data       # potentially dangerous if format string is user-controlled
```

## Part 4: Integer overflow and underflow

Integer overflows in security-sensitive contexts: size calculations, index bounds, loop counters.

```c
// Flag: unsigned underflow used as size
size_t len = user_supplied_length;
size_t remaining = BUFFER_SIZE - len;  // underflow if len > BUFFER_SIZE
memcpy(dst, src, remaining);           // extremely large copy

// Flag: signed/unsigned comparison
int user_idx = atoi(user_input);       // can be negative
if (user_idx < MAX_SIZE) {             // passes for negative values
    buffer[user_idx] = value;          // negative index → out-of-bounds write
}

// Flag: truncation of larger type to smaller
int count = user_supplied_count;       // may be 0x80000001 → negative when int
size_t alloc = (unsigned)count * sizeof(item);  // reinterpretation

// Safe pattern: validate bounds before arithmetic
if (len > BUFFER_SIZE) { return ERROR; }
```

## Part 5: Null pointer dereference

```c
// Flag: return value of malloc/calloc/realloc not checked
ptr = malloc(size);
ptr->field = value;        // null deref if malloc fails under memory pressure

// Flag: return value of functions that can return NULL
FILE *f = fopen(path, "r");
fread(buf, 1, size, f);    // null deref if fopen failed

// Flag: function parameter assumed non-null
void process(char *input) {
    int len = strlen(input);   // null deref if caller passes NULL
}
```

## Part 6: Unsafe Rust

```rust
// Flag: unsafe dereferencing without validation
unsafe {
    let val = *ptr;               // is ptr valid? non-null? aligned?
    let slice = std::slice::from_raw_parts(ptr, len);  // is len valid?
}

// Flag: transmute of user-controlled data
unsafe {
    let val: &SomeStruct = std::mem::transmute(user_bytes.as_ptr());
}

// Flag: FFI calls with user-controlled lengths
extern "C" fn copy_data(dst: *mut u8, src: *const u8, len: usize) {
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, len);  // len validated?
    }
}
```

## Part 7: Input-reachability triage

For each memory safety issue found, determine if it is reachable from user-controlled input:

1. **Directly reachable**: user input flows into the vulnerable operation in the same function
2. **Reachable via call chain**: user input is passed to a function that eventually reaches the vulnerability
3. **Conditionally reachable**: requires specific input values to trigger (e.g., length > 256, specific format)
4. **Not reachable from user input**: vulnerability exists but only in internal code paths

Only report reachable findings as vulnerabilities. Note unreachable ones as lower-priority code quality issues.

## Output format

```json
{
  "file": "src/parser.c",
  "line": 142,
  "category": "stack_buffer_overflow",
  "title": "Stack buffer overflow via unbounded strcpy with HTTP header value",
  "description": "strcpy(buf, header_value) copies a user-supplied HTTP header into a 256-byte stack buffer without length check. An attacker can overflow the stack with a header value > 256 bytes.",
  "evidence": "char buf[256]; strcpy(buf, header_value);  // line 141-142",
  "taint_source": "header_value derived from HTTP header at parse_request() line 88",
  "reachability": "directly_reachable",
  "exploitability": "Stack canary may or may not be present. If absent, direct EIP control.",
  "remediation": "Replace with: strncpy(buf, header_value, sizeof(buf) - 1); buf[sizeof(buf)-1] = '\\0'; Or use dynamic allocation with validated length.",
  "cwe": "CWE-121",
  "severity": "critical"
}
```
