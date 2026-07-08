1. Privilege Separation and Malware Analysis Sandbox

A Program and operating system coursework project implementing two Linux systems security
mechanisms in C, using only POSIX/Linux system calls: process fork/exec,
UNIX domain sockets, privilege dropping, and pthread-based resource
monitoring.

Overview

This repository contains two independent tasks:

Task 1 — Privilege-Separated Authentication System

  A password validation system split into two processes (`Frontend` and
  `Backend`) communicating over a UNIX domain socket. The Backend starts
  with elevated privileges, validates credentials, then permanently drops
  privileges using `setresuid()` and verifies the drop with `geteuid()`.

Task 2 — User-Space Malware Analysis Sandbox
  A sandbox (`Sandbox.c`) that runs an untrusted binary in a forked child
  process via `execve()`, while the parent monitors execution time, CPU
  usage, and memory usage using `SIGALRM`, `pthread`, and `getrusage()`,
  terminating the child if it exceeds configured limits.

Prerequisites

- Ubuntu Linux or WSL
- GCC
- POSIX threads (`-pthread`)
- `make` (optional, if using the provided Makefiles)

Repository Structure