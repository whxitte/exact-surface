# ExactSurface Workbench — internal module test bench

**Full documentation: [`docs/DEVTOOLS.md`](../docs/DEVTOOLS.md)** — read it before running
this. It covers why the workbench is a separate app, how it is contained, and how to use it.

```bash
python -m devtools
```

It prints the only URL that works. The token is new on every start, never written to disk,
and without it every path returns 404.

## The three things you must know

1. **This is not part of the product.** It adds no endpoint to the ExactSurface API, is
   never copied into any image, and refuses to start when `EXACTSURFACE_ENV=prod`.

2. **It bypasses the scope engine.** That is its purpose — you can call `nuclei_scan(url)`
   with a URL you typed. **You are the control.** Only ever point it at hosts you own or
   are explicitly authorised to test. Nothing here is enforcing that for you.

3. **Do not change the bind address, and do not put it behind a proxy.** Loopback plus
   the `Host` allow-list is what defeats DNS rebinding. Use an SSH tunnel if you need it
   from elsewhere: `ssh -L 8765:127.0.0.1:8765 you@devbox`.
