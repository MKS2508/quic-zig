# Claude Code Configuration for quic-zig

> ## 📍 El planning de waxin para este repo vive en `mesh`
>
> Este es un **fork de `endel/quic-zig`**. Casi toda la documentación del repo
> (`README.md`, `PRIORITIES.md`, `SPEC/*`, `BENCHMARK.md`, `DECISIONS/*`) es **del fork
> padre**, no de waxin. Este `CLAUDE.md` es lo único suyo.
>
> Las lanes planificadas que tocan este repo, y las decisiones que las gobiernan, están en:
>
> **`/Volumes/KODAK1TB/REPOS y PROYECTOS/nodejs-bun/mesh`** (`MKS2508/mesh`, rama `main`)
>
> | Leer esto primero | Qué es |
> |---|---|
> | `docs/research/2026-09-03-mapa-cross-repo.md` | **Empieza aquí.** El mapa de los 10 repos: qué existe de verdad y qué es prosa |
> | `docs/task-requests/quicz-windows.plan.md` | Plan de soporte Windows. Su **M6a y M6b aterrizan en el fork `MKS2508/libxev`**, no aquí |
> | `docs/task-requests/quicz-qnt.plan.md` | Plan de NAT traversal (QNT) |
> | `roadmap.spec.yml` → **D-051, D-061, D-064** | El ledger manda sobre la prosa |
>
> 🔴 **Ojo: hay DOS ledgers vivos** — `mesh/roadmap.spec.yml` y `zkit/zkit.model.yml` — y no
> se conocen entre sí. No tomes decisiones estructurales sin mirar los dos.

## 🔴 `zig-pkg/` es caché local, NO una dependencia vendorizada

**Esto se documentó mal y se corrigió midiéndolo.** Si te encuentras la afirmación
*"`zig-pkg/` es el workaround, hay que re-vendorizar a mano en cada bump"* en cualquier sitio
—incluido el `CLAUDE.md` del fork de libxev, o docs de `mesh`— **es falsa**. Está desmentida
por el commit **`cf68ecc`** de este repo, con medición en los dos sentidos:

- `zig fetch libxev@c1e223b` con caché aislada vacía → **EXIT=0**, y devuelve exactamente el
  hash que pinnea el `.zon`. Control positivo: `zkit` fetcha igual de bien, y los dos emiten
  el mismo warning `DirNotEmpty` — o sea que **ese síntoma no discrimina nada**.
- Clean room, clon limpio, dos cachés aisladas independientes:
  **con `zig-pkg` → 51/51 steps; sin `zig-pkg` → 51/51 steps y cero errores de resolución.**
  El package store de la corrida sin `zig-pkg` tiene una sola entrada, y es la pinneada.

Los 88 ficheros entraron solos porque el `.gitignore` llevaba `.zig-cache` pero **no**
`zig-pkg`. `styx` tiene el mismo directorio y **sí** lo ignora — ese contraste es lo que
cerró el diagnóstico. Hoy `.gitignore:8` ya lo cubre.

**Consecuencia práctica: un bump de libxev es `zig fetch --save`, y ya.** No hay que
re-vendorizar nada.

Durante desarrollo, para iterar contra un checkout local del fork sin pasar por fetch:
`zig build --fork=<path>`.

## D-064 — por qué Windows se arregla en el fork de libxev, no aquí

`quic-zig` no compila para Windows. El bloqueante estructural **no** es el
`@compileError` de `sys.sendto` (`src/sys.zig:191`): es que el event loop llama
`xev.File.poll(.read)` (`src/event_loop.zig:498,501`) y **el backend IOCP de libxev no
implementa `poll`** (`src/watcher/stream.zig:101,282,301`). IOCP es *completion-based*; el
modelo de *readiness* sobre el que se apoya este event loop no existe en Windows.

Y `src/c_api.zig:269` es `server: event_loop.Server(CApiHandler)`, así que **los 18
`export fn qz_*` están en la ruta afectada** — no es una app de demo.

waxin eligió arreglarlo **en la capa correcta**: implementar el op `poll` que falta en el
backend IOCP, vía **AFD** (la superficie NT que usan libuv, tokio y mio para exactamente
esto). Se descartó un seam `Poller` dentro de este repo, que era más barato. **`quic-zig` no
se toca ni una línea.**

## Ramas: cuáles son de waxin y cuáles no

Verificado comparando `origin/X` contra `upstream/X`:

| Rama | Dueño |
|---|---|
| `main`, `bbr-v3`, `wasm-experiment`, `perf-experiment`, `udp-send-optimizations`, `fix/disconnect-detection`, `debug/zerortt-quic-go-interop` | **`endel/quic-zig`** — mirrors byte-idénticos |
| `unify/zig-0.17`, `feat/zig-0.17`, `pr/disposal-on-ack-lifecycle` | **waxin** |

⚠️ `main` **ya no** es mirror de upstream: lleva la migración a Zig 0.17 (`1893`) y el pin
del fork propio de libxev.

## Toolchain

`0.17.0-dev.1893+78e3b1c73`, declarado en `build.zig.zon`, **aplicado** por un guard de
comptime en `build.zig` y ahora también pinneado en el CI (`.github/workflows/test.yml`).

🔴 El `minimum_zig_version` del `.zon` es **advisory** — el build runner no lo comprueba
nunca. **Lo único que para un build en el compilador equivocado es el bloque comptime.**

⚠️ **Deuda con fecha de caducidad**: el README de `mlugg/setup-zig` avisa de que los mirrors,
ziglang.org incluido, purgan nightlies viejos cuando quieren. Este pin puede romper el CI
solo, sin que nadie toque nada.
