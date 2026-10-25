# FreeBSD Upstream Kernel Vulnerability & Patch Sentinel

> **Entidad:** García Casado Security Research  
> **Último escaneo:** `2026-10-25 18:24:02`  
> **Commits analizados:** `75` en `5` subsistemas críticos  
> **Alertas activas:** `24` hallazgos con patrones de fallo de memoria  

---

## 🎯 Resumen de Hallazgos Filtrados para Orbis OS (PS4 FW 14.00)

### 1. [9a406a9e] tcp/rack: Fix a potential overflow in rack_update_pcm_ack()
- **Subsistema:** `sys/netinet` (Pila de Red IPv4/IPv6 / Mbufs / Sockets)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `40`)
- **Fecha:** `2026-10-12T18:55:21Z` | **Autor:** `Michael Tuexen`
- **Enlace al Commit:** [9a406a9e](https://github.com/freebsd/freebsd-src/commit/9a406a9ec399cced14ce5d204ba3fd383544b47f)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\boverflow\b'
  - Alta criticidad: coincide con '\bout-of-bounds\b'
  - Alta criticidad: coincide con '\bcve-\d{4}-\d+\b'
  - Alta criticidad: coincide con '\bsecurity\b'
- **Mensaje Completo:**
```text
tcp/rack: Fix a potential overflow in rack_update_pcm_ack()

The RACK stack's path capacity measurement module maintains an array of
samples, updated when the stack receives an ACK.  The array grows as
needed, but code which handles the expansion is susceptible to remotely
triggerable overflow.  This could lead to underallocation and a ~512KB
out-of-bounds write.

Fix this by bounding the sample a...
```

### 2. [47d2d509] sound: Revalidate after reacquiring locks when resizing buffers
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `25`)
- **Fecha:** `2026-10-13T15:54:07Z` | **Autor:** `Mark Johnston`
- **Enlace al Commit:** [47d2d509](https://github.com/freebsd/freebsd-src/commit/47d2d509c6b32b3c2245748f755fbf2344351d94)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\bcve-\d{4}-\d+\b'
  - Alta criticidad: coincide con '\bsecurity\b'
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Revalidate after reacquiring locks when resizing buffers

sndbuf_resize() and sndbuf_remalloc() drop the channel lock in order to
allocate the new buffer(s) with M_WAITOK.  Before doing that they verify
that the buffer is not mapped, but this could change while the lock is
dropped, as there is no higher-level synchronization which prevents
buffer resize (e.g., via the SNDCTL_DSP_SETBLKSIZE ...
```

### 3. [f51a5e1d] uma: Insert KASAN redzones after slab-allocated items
- **Subsistema:** `sys/vm` (Gestión de Memoria Virtual / Slab Allocator / UMA)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `24`)
- **Fecha:** `2026-07-31T12:55:48Z` | **Autor:** `Mark Johnston`
- **Enlace al Commit:** [f51a5e1d](https://github.com/freebsd/freebsd-src/commit/f51a5e1d9c415d97b86f0f2c8da9cc9ad9dc683b)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\boverflow\b'
  - Alta criticidad: coincide con '\bunderflow\b'
  - Media criticidad: coincide con '\bpanic\b'
- **Mensaje Completo:**
```text
uma: Insert KASAN redzones after slab-allocated items

Without this, KASAN has the deficiency that inter-object overflows are
not detected most of the time[*] when keg_layout() is able to perfectly
pack a slab.  Try to overcome this by adjusting the allocation size to
include a redzone following the object.

With this change, we automatically get a redzone following each item, so
any overflow into...
```

### 4. [3545fc68] sound: Check for errors from sndbuf_resize()
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `15`)
- **Fecha:** `2026-10-13T15:53:39Z` | **Autor:** `Mark Johnston`
- **Enlace al Commit:** [3545fc68](https://github.com/freebsd/freebsd-src/commit/3545fc68f416ee6d3379e0a44ed9eb22fefee2ef)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\bsecurity\b'
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Check for errors from sndbuf_resize()

Most implementations of CHANNEL_SETBLOCKSIZE and CHANNEL_SETFRAGMENTS
were not checking this.  This is probably not a big problem: it's
unlikely for sndbuf_resize() to fail due to the refcount check in this
case since it's operating on the hardware buffer, which doesn't get
mmaped.  But, I will add more reasons for it to fail in the next patch,
so let'...
```

### 5. [742e58dd] vm_page: Fix the error path in vm_page_alloc_contig_domain()
- **Subsistema:** `sys/vm` (Gestión de Memoria Virtual / Slab Allocator / UMA)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `14`)
- **Fecha:** `2026-09-24T15:49:37Z` | **Autor:** `Mark Johnston`
- **Enlace al Commit:** [742e58dd](https://github.com/freebsd/freebsd-src/commit/742e58ddc989563f90a1d636cb29793641784ca1)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\bunderflow\b'
  - Media criticidad: coincide con '\bpanic\b'
- **Mensaje Completo:**
```text
vm_page: Fix the error path in vm_page_alloc_contig_domain()

If we are inserting a run of pages into a VM object and fail at some
point due to a memory allocation failure, we have to free all of the
pages in the run.  We do that by resetting some fields and calling
vm_page_free_toq() on each page; this removes the page from the object
and frees it back to the buddy allocator.

If the page is supp...
```

### 6. [d6915bff] nullfs: close a race when syncing inotify flags from the lower vnode
- **Subsistema:** `sys/fs/nullfs` (Sistemas de Ficheros NullFS (Montajes loopback / Sandbox))
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `14`)
- **Fecha:** `2026-07-19T07:38:52Z` | **Autor:** `Alexander Leidinger`
- **Enlace al Commit:** [d6915bff](https://github.com/freebsd/freebsd-src/commit/d6915bffb7b68d9b55fa3db4e5709463549c379e)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\bracing\b'
  - Media criticidad: coincide con '\brace\b'
- **Mensaje Completo:**
```text
nullfs: close a race when syncing inotify flags from the lower vnode

After a bypassed VOP, nullfs mirrors the lower vnode's inotify state
onto the upper vnode.  The flags were checked with lockless reads
before being updated with the asserting flag set/unset primitives, so
two threads syncing the same vnode concurrently (or a sync racing a
watch being established) could both decide to make the sa...
```

### 7. [2c68ad49] nullfs: Allow VSOCK to be mounted on top of another VSOCK
- **Subsistema:** `sys/fs/nullfs` (Sistemas de Ficheros NullFS (Montajes loopback / Sandbox))
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `10`)
- **Fecha:** `2026-08-28T05:12:46Z` | **Autor:** `Jesús Daniel Colmenares Oviedo`
- **Enlace al Commit:** [2c68ad49](https://github.com/freebsd/freebsd-src/commit/2c68ad49f13ddfa33735bd9bb6a3ca170a472ac0)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\bsecurity\b'
- **Mensaje Completo:**
```text
nullfs: Allow VSOCK to be mounted on top of another VSOCK

In the world of containers, mounting a unix(4) socket is a common
practice to allow communication between processes within containers.
For example, both Podman and Docker can expose a unix(4) socket,
and that same unix(4) socket can be mounted as a file accessible
to a process inside a container, allowing that application to control
Podman...
```

### 8. [990989c3] uma: Make an effort to defer reuse of items when KASAN is enabled
- **Subsistema:** `sys/vm` (Gestión de Memoria Virtual / Slab Allocator / UMA)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `10`)
- **Fecha:** `2026-07-24T21:12:10Z` | **Autor:** `Mark Johnston`
- **Enlace al Commit:** [990989c3](https://github.com/freebsd/freebsd-src/commit/990989c31b4637a23e64598a3d9929079bb9a8de)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\buse-after-free\b'
- **Mensaje Completo:**
```text
uma: Make an effort to defer reuse of items when KASAN is enabled

When KASAN is configured, make uma_zfree_arg() free items to the per-CPU
free bucket, rather than to the alloc bucket.  This means that the item
won't be recycled immediately the next time a thread goes to allocate an
item from that zone on the same CPU.  In other words, the item will stay
in a quarantine state longer, which helps ...
```

### 9. [6337ca19] uma: Factor out the implementations of uma_zfree_{arg,smr}()
- **Subsistema:** `sys/vm` (Gestión de Memoria Virtual / Slab Allocator / UMA)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `10`)
- **Fecha:** `2026-07-24T21:11:58Z` | **Autor:** `Mark Johnston`
- **Enlace al Commit:** [6337ca19](https://github.com/freebsd/freebsd-src/commit/6337ca19a3637aa72eddf4d62a2eaf7d8df51638)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\buse-after-free\b'
- **Mensaje Completo:**
```text
uma: Factor out the implementations of uma_zfree_{arg,smr}()

The two function both free an item to a UMA zone, but uma_zfree_arg()
does so in such as way as to ensure that the item will be the first one
returned by a subsequent allocation, while uma_zfree_smr() must defer
reuse of the item and therefore never frees to the per-CPU alloc bucket.

When KASAN is enabled, we actually want uma_zfree_ar...
```

### 10. [2efe148a] exec: Avoid overflow when computing the size of the exec map
- **Subsistema:** `sys/vm` (Gestión de Memoria Virtual / Slab Allocator / UMA)
- **Nivel de Criticidad:** `ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)` (Score: `10`)
- **Fecha:** `2026-07-21T22:30:53Z` | **Autor:** `Mark Johnston`
- **Enlace al Commit:** [2efe148a](https://github.com/freebsd/freebsd-src/commit/2efe148a2a321d4c9ed46bdb166f710b2cb21529)
- **Indicadores de Detección:**
  - Alta criticidad: coincide con '\boverflow\b'
- **Mensaje Completo:**
```text
exec: Avoid overflow when computing the size of the exec map

On a test system with 1024 cores the size of exec map exceeds 4GB, and
all of the operands in the size calculation are 32-bit integers.

Tested by:	Jim Huang Chen <jim.chen.1827@gmail.com>
MFC after:	1 week
Sponsored by:	AMD (hardware)
```

### 11. [8dac0bdb] snd_hda: Identify AMD Audio Coprocessor
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-10-25T10:21:20Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [8dac0bdb](https://github.com/freebsd/freebsd-src/commit/8dac0bdb4df0815e14db219e9a7fb5d0be5737b8)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
snd_hda: Identify AMD Audio Coprocessor

This makes the driver attach, but the device is still not usable.

Reported by:	Lukasz Wencki <lukasz@smail.net.pl>
MFC after:	1 week
Sponsored by:	The FreeBSD Foundation
```

### 12. [20381bce] sound: Remove obsolete comment from sound.h
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-10-08T13:11:21Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [20381bce](https://github.com/freebsd/freebsd-src/commit/20381bce4b63975494a2f4bc84257f6932e6d379)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Remove obsolete comment from sound.h

MFC after:	1 week
Sponsored by:	The FreeBSD Foundation
```

### 13. [25faf861] pcm.4: Remove DIAGNOSTICS section
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-10-07T07:03:31Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [25faf861](https://github.com/freebsd/freebsd-src/commit/25faf861089ca119528ea4da39fe594b1c5ca55a)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
pcm.4: Remove DIAGNOSTICS section

These diagnostics do not exist anymore.

MFC after:	1 week
```

### 14. [29449b3e] snd_hda: use the pin ELD to select DisplayPort audio framing
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-10-03T14:04:32Z` | **Autor:** `David Bidner`
- **Enlace al Commit:** [29449b3e](https://github.com/freebsd/freebsd-src/commit/29449b3e468cb1673814dc6452e82035b3c2a628)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
snd_hda: use the pin ELD to select DisplayPort audio framing

hdaa_audio_setup() reads the converter widget's ELD when choosing
between HDMI and DisplayPort audio infoframes. ELD is stored on the
output pin, so the converter has no ELD and the driver selects HDMI
framing even when the connected display uses DisplayPort.

Read the ELD from the output pin to select the correct audio framing.

The eq...
```

### 15. [32137c41] sound: Retire the version constants
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-22T17:34:16Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [32137c41](https://github.com/freebsd/freebsd-src/commit/32137c41065c3fa101bf0056b76889b98a7492cb)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Retire the version constants

They exist only to fill in MODULE_DEPEND() and MODULE_VERSION(), and
every consumer passed the same value for all three, so the version
range never did anything. Use 1, like the rest of the tree does.

MFC after:	1 week
Sponsored by:	The FreeBSD Foundation
Reviewed by:	kib, emaste
Differential Revision:	https://reviews.freebsd.org/D59873
```

### 16. [2793e549] sound: Use uint8_t instead of legacy u_char
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-22T16:11:23Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [2793e549](https://github.com/freebsd/freebsd-src/commit/2793e5498dd9bceada62ebe38967d89180bd15f6)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Use uint8_t instead of legacy u_char

No functional change intended.

MFC after:	1 week
Sponsored by:	The FreeBSD Foundation
```

### 17. [47cf9dc7] sound: Lock around mixer_set*() in mixer_init() for consistency
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-18T18:18:20Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [47cf9dc7](https://github.com/freebsd/freebsd-src/commit/47cf9dc7861371edcfdb85a38e2c240f430ccb28)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Lock around mixer_set*() in mixer_init() for consistency

Sponsored by:	The FreeBSD Foundation
MFC after:	1 month
Differential Revision:	https://reviews.freebsd.org/D59110
```

### 18. [044ef293] sound: Remove unncessary locking in sysctl_hw_snd_hwvol_mixer()
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-18T18:18:13Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [044ef293](https://github.com/freebsd/freebsd-src/commit/044ef293a8bbd057de3fb13ec97d3d0ee16462e4)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Remove unncessary locking in sysctl_hw_snd_hwvol_mixer()

The locking around strlcpy() was because of m->hwvol_mixer, but this is
just an int, so we don't need to lock in this case. Instead lock only
when m->hwvol_mixer is written.

While here, add parentheses around the returns.

Sponsored by:	The FreeBSD Foundation
MFC after:	1 month
Differential Revision:	https://reviews.freebsd.org/D591...
```

### 19. [db62d784] sound: Improve some mixer return values and their handling
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-18T18:18:10Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [db62d784](https://github.com/freebsd/freebsd-src/commit/db62d784f02a913c7fca612b04585c633ba8277c)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Improve some mixer return values and their handling

Sponsored by:	The FreeBSD Foundation
MFC after:	1 month
Differential Revision:	https://reviews.freebsd.org/D59078
```

### 20. [6c735475] sound: Reuse mixer_delete() in mixer_uninit()
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-18T18:18:01Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [6c735475](https://github.com/freebsd/freebsd-src/commit/6c735475aeefc626962818c0ab8749aaeb6de9a4)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Reuse mixer_delete() in mixer_uninit()

Sponsored by:	The FreeBSD Foundation
MFC after:	1 month
Differential Revision:	https://reviews.freebsd.org/D59077
```

### 21. [03b59d2e] sound: Do not set a recording source in mixer_uninit()
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-18T18:16:40Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [03b59d2e](https://github.com/freebsd/freebsd-src/commit/03b59d2e7df263ea5a8904e5593d14f6e3e0fbd8)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Do not set a recording source in mixer_uninit()

We currently set the recording source to SOUND_MIXER_MIC during mixer
deletion. Apart from the fact that this control might not be present on
all devices, it is unnecessary to do that, plus we already set all the
volumes to 0 in the mixer_set() call above.

Sponsored by:	The FreeBSD Foundation
MFC after:	1 month
Differential Revision:	https:/...
```

### 22. [9548bfa3] sound: Retire mixer_hwvol locked variants
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2026-09-18T18:16:03Z` | **Autor:** `Christos Margiolis`
- **Enlace al Commit:** [9548bfa3](https://github.com/freebsd/freebsd-src/commit/9548bfa342a71f1ca0ad953bf323086e84a395c3)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Retire mixer_hwvol locked variants

Prior to 9a00e0b8ca56 ("snd_uaudio: Do not use snd_mixer->lock as
mixer_lock"), there was a need for mixer_hwvol_mute_locked() and
mixer_hwvol_step_locked(), because the unlocked variants would acquire
the lock, but uaudio_hid_rx_callback() would also hold the lock, so this
was a measure to avoid recursion on snd_mixer->lock. Now that
snd_uaudio(4) has a ...
```

### 23. [dd51cef5] sound: Whitespace cleanup
- **Subsistema:** `sys/dev/sound` (Controladores de Audio sound(4) / Búfers mmap)
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `5`)
- **Fecha:** `2023-12-02T02:42:36Z` | **Autor:** `Ed Maste`
- **Enlace al Commit:** [dd51cef5](https://github.com/freebsd/freebsd-src/commit/dd51cef58311ee0024be99116238d1c0032bdf2b)
- **Indicadores de Detección:**
  - Subsistema crítico presente en Orbis OS (sys/dev/sound)
- **Mensaje Completo:**
```text
sound: Whitespace cleanup

In advance of additional sound(4) work, remove EOL whitespace and mixed
tab/space.

Reviewed by:	christos
Differential Revision: https://reviews.freebsd.org/D60442
```

### 24. [09f925b5] nullfs: Slightly reduce contention by reducing concurrent sections
- **Subsistema:** `sys/fs/nullfs` (Sistemas de Ficheros NullFS (Montajes loopback / Sandbox))
- **Nivel de Criticidad:** `MODERADA (REVISAR DIF)` (Score: `4`)
- **Fecha:** `2025-10-06T13:22:13Z` | **Autor:** `Olivier Certner`
- **Enlace al Commit:** [09f925b5](https://github.com/freebsd/freebsd-src/commit/09f925b57aeb171318a9d54df500bf22b4cdd986)
- **Indicadores de Detección:**
  - Media criticidad: coincide con '\bunlock\b'
- **Mensaje Completo:**
```text
nullfs: Slightly reduce contention by reducing concurrent sections

In null_lock_prep_with_smr(), initialize 'lvp' outside of the
SMR-protected section.

In null_lock(), if after locking the lower vnode we notice that we have
been reclaimed, we have to unlock the lower vnode and then relock our
own now that the lock isn't shared anymore.  Call VOP_UNLOCK() on the
lower vnode as soon as this condit...
```
