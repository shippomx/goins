# goins

An interactive tool to analyze Golang goroutine dump.

## Build and Run

```bash
go get github.com/shippomx/goins
$GOPATH/bin/goins
```

## Workspace

Workspace is the place to hold imported goroutine dumps. Instructions are
provided to maintain these dumps.

In the interactive shell, two kinds of instructions can be issued: commands
and statements.

## Commands

At present, the following commands are supported.

| command | function                          |
| ------- | --------------------------------- |
| cd      | Change current working directory. |
| clear   | Clear the workspace.              |
| exit    | Exit the interactive shell.       |
| help    | Show help.                        |
| ls      | Show files in current directory.  |
| pwd     | Show present working directory.   |
| quit    | Quit the interactive shell.       |
| whos    | Show all varaibles in workspace.  |

## Statements

### Load Goroutine Dump From Files

Load the dump and assign to a variable:

```bash
>> original = load("pprof-goroutines-20170510-170245.dump")
>> whos
original
```

### Show the Summary of a Dump Var

Simply type the variable name:

```bash
>> original
# of goroutines: 2217

        running: 1
        IO wait: 533
        syscall: 2
   chan receive: 50
         select: 1504
       runnable: 38
     semacquire: 85
      chan send: 4

```

### Copy a Dump Var

To copy the whole dump, simply assign it to a different var:

```bash
>> copy1 = original
>> whos
copy        original
```

It's equivalent to using a copy() function:

```bash
>> copy2 = original.copy()
>> whos
copy        copy1        copy2        original
```

The copy() function allows passing a conditional so that only those meeting
the cariteria will be copied:

```bash
>> copy3 = original.copy("id>900 && id<2000")
```

### Modify the Dump Goroutine Items

Function delete() accepts a conditional to delete goroutine items in a dump
var. Function keep() do the reversed conditional.

```bash
>> copy
# of goroutines: 2217

        running: 1
        IO wait: 533
        syscall: 2
   chan receive: 50
         select: 1504
       runnable: 38
     semacquire: 85
      chan send: 4

>> copy.delete("id>100 && id<1000")
Deleted 118 goroutines, kept 2099.
>> copy.keep("id>200")
Deleted 12 goroutines, kept 2087.
>> copy
# of goroutines: 2087

        running: 1
         select: 1411
        IO wait: 500
     semacquire: 85
       runnable: 37
   chan receive: 49
      chan send: 4

```

### Display Goroutine Dump Items

Function show() displays goroutine dump items with optional offset and limit.
The default offset is 0, and default limit is 10.

```bash
>> original.show() # offset 0, limit 10

goroutine 1803 [select, 10 minutes]:
google.golang.org/grpc/transport.(*http2Server).keepalive(0xc420e59ce0)
        google.golang.org/grpc/transport/http2_server.go:919 +0x488
created by google.golang.org/grpc/transport.newHTTP2Server
        google.golang.org/grpc/transport/http2_server.go:226 +0x97c

...
...

>> original.show(15) # offset 15, limit 10

goroutine 6455709 [running]:
runtime/pprof.writeGoroutineStacks(0xe9a080, 0xc4216f0088, 0x1d, 0x40)
        go1.8.1.linux-amd64/src/runtime/pprof/pprof.go:603 +0x79
runtime/pprof.writeGoroutine(0xe9a080, 0xc4216f0088, 0x2, 0x1d, 0xc4217cede0)
        go1.8.1.linux-amd64/src/runtime/pprof/pprof.go:592 +0x44
runtime/pprof.(*Profile).WriteTo(0xed3780, 0xe9a080, 0xc4216f0088, 0x2, 0xc4217cef80, 0x1)
        go1.8.1.linux-amd64/src/runtime/pprof/pprof.go:302 +0x3b5
www.test.com/bagel/runtime.dumpToFile(0xed0f0ba5e, 0xae05027, 0xee1780, 0xc425bd2060, 0x5, 0x5)
        www.test.com/bagel/runtime/dump.go:58 +0x3f3
created by www.test.com/bagel/runtime.EnableGoroutineDump.func1
        www.test.com/bagel/runtime/dump.go:30 +0x2d6

...
...

>> original.show(15, 1) # offset 15, limit 1

goroutine 6455709 [running]:
runtime/pprof.writeGoroutineStacks(0xe9a080, 0xc4216f0088, 0x1d, 0x40)
        go1.8.1.linux-amd64/src/runtime/pprof/pprof.go:603 +0x79
runtime/pprof.writeGoroutine(0xe9a080, 0xc4216f0088, 0x2, 0x1d, 0xc4217cede0)
        go1.8.1.linux-amd64/src/runtime/pprof/pprof.go:592 +0x44
runtime/pprof.(*Profile).WriteTo(0xed3780, 0xe9a080, 0xc4216f0088, 0x2, 0xc4217cef80, 0x1)
        go1.8.1.linux-amd64/src/runtime/pprof/pprof.go:302 +0x3b5
www.test.com/bagel/runtime.dumpToFile(0xed0f0ba5e, 0xae05027, 0xee1780, 0xc425bd2060, 0x5, 0x5)
        www.test.com/bagel/runtime/dump.go:58 +0x3f3
created by www.test.com/bagel/runtime.EnableGoroutineDump.func1
        www.test.com/bagel/runtime/dump.go:30 +0x2d6
```

### Search Goroutine Dump Items

Similar to show(), but with a conditional to only show items meeting certain
criteria:

```bash
>> original.search("id < 2000", 15, 1) # offset 15, limit 1

goroutine 6455896 [select]:
net.(*netFD).connect.func2(0xea1980, 0xc424bca540, 0xc422c1af50, 0xc424bca600, 0xc424bca5a0)
        go1.8.1.linux-amd64/src/net/fd_unix.go:133 +0x1d5
created by net.(*netFD).connect
        go1.8.1.linux-amd64/src/net/fd_unix.go:144 +0x239
```

One useful ability is to filter goroutines by running time:

```bash
>> original.search("duration > 10") # duration larger than 10 minutes

goroutine 72 [select, 25 minutes]: 119 times: [72, 54755, 76757, 299, 201, 286, 283, 296, 204, 302, 
207, 305, 338, 356, 359, 362, 365, 372, 375, 368, 378, 328, 331, 387, 381
, 390, 384, 403, 393, 334, 406, 396, 399, 337, 418, 341, 436, 344, 439, 421, 424, 409, 427, 452, 430, 433, 442, 455, 445, 458, 448, 461, 464, 468, 483, 471, 499, 486, 502, 5
05, 489, 76462, 76773, 54530, 54572, 55194, 54824, 54481, 42719, 54691, 54859, 55023, 75593, 76750, 55202, 54885, 79006, 54468, 55212, 54473, 54462, 54931, 54864, 55133, 550
97, 54882, 54901, 55209, 54499, 55114, 54564, 76653, 54416, 54527, 75588, 55034, 54868, 54791, 54813, 54698, 54579, 55111, 54443, 54486, 76467, 54654, 54537, 54456, 55126, 5
5117, 54622, 55199, 54556, 54477, 54871, 79498, 76601, 76735, 76996]
google.golang.org/grpc/transport.(*http2Server).keepalive(0xc4202f0420)
        google.golang.org/grpc/transport/http2_server.go:919 +0x488
created by google.golang.org/grpc/transport.newHTTP2Server
        google.golang.org/grpc/transport/http2_server.go:226 +0x97c
```

Note that the above is after a dedup operation, so it shows the same stack trace
existing 119 times. See the "Dedup goroutines" section.

### Diff Two Goroutine Dumps

```bash
>> l, c, r = x.diff(y)
>> l
# of goroutines: 574

        IO wait: 147
   chan receive: 1
       runnable: 3
         select: 421
        syscall: 2

>> c
# of goroutines: 651

        IO wait: 157
       runnable: 4
         select: 489
     semacquire: 1

>> r
# of goroutines: 992

        IO wait: 229
   chan receive: 49
      chan send: 4
       runnable: 31
        running: 1
         select: 594
     semacquire: 84
```

It returns three values: the dump var containing goroutines only appear in
x (the left side), the dump var containing goroutines appear in both x and y,
the dump var containing goroutines only appear in y (the right side).

### Dedup goroutines

Normally goroutine dump files contain thousands of goroutine entries, but
there are many duplicated traces. Function dedup() helps to identify these
duplicated traces by comparing the trace lines, and only keep one copy of
them. It greatly reduces the information explosion and make developers much
easier to focus on their problems.

```bash
>> a
# of goroutines: 2217

        IO wait: 533
   chan receive: 50
      chan send: 4
       runnable: 38
        running: 1
         select: 1504
     semacquire: 85
        syscall: 2

>> a.dedup()
Dedupped 2217, kept 46
>>
>> a
# of goroutines: 46

        IO wait: 6
   chan receive: 2
      chan send: 2
       runnable: 18
        running: 1
         select: 12
     semacquire: 3
        syscall: 2
```

To show goroutines with 5+ duplicates:

```bash
>> a.search("dups >= 5")
   ...
```

### check goroutines
Check goroutine entries have surspicous goroutine deaklock.
```bash
>> a.check()
Dedupped 1453, kept 39
================= WARNING DEAD LOCK =================

goroutine 67777 has surspicous DEAD LOCK with goroutine 66926
LockHolders of goroutine 67777: [*Mutex *RWMutex *memoryStore *Daemon]
LockHolders of goroutine 66926: [*Mutex *State *Daemon *memoryStore *Daemon]
```

### Save the Modified Goroutine Dump to a File

After a dump var is modified, it can be saved to a file:

```bash
>> a.save("pprof-deduped.log")
```

## Properties of a Goroutine Dump Item

Each dump item has 5 properties which can be used in conditionals:

| property | type    | meaning                                             |
| -------- | ------- | --------------------------------------------------- |
| id       | integer | The goroutine ID.                                   |
| dups     | integer | The number of duplicate traces.                     |
| duration | integer | The waiting duration (in minutes) of a goroutine.   |
| lines    | integer | The number of lines of the goroutine's stack trace. |
| state    | string  | The running state of the goroutine.                 |
| trace    | string  | The concatenated text of the goroutine stack trace. |

## Functions in Conditionals

The following functions can be used in defining conditionals:

| function | args           | return value | meaning                                               |
| -------- | -------------- | ------------ | ----------------------------------------------------- |
| contains | string, string | bool         | Returns true if the first arg contains the second arg |
| lower    | string         | string       | Returns the lowercased string of the input.           |
| upper    | string         | string       | Returns the uppercased string of the input.           |

Example:

```bash
>> original.search("contains(lower(trace), 'handlestream')")
```
