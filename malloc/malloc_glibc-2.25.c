/* Malloc implementation for multiple threads without lock contention.
   Copyright (C) 1996-2017 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Wolfram Gloger <wg@malloc.de>
   and Doug Lea <dl@cs.oswego.edu>, 2001.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, see <http://www.gnu.org/licenses/>.  */

/*
  This is a version (aka ptmalloc2) of malloc/free/realloc written by
  Doug Lea and adapted to multiple threads/arenas by Wolfram Gloger.

  There have been substantial changes made after the integration into
  glibc in all parts of the code.  Do not look for much commonality
  with the ptmalloc2 version.

* Version ptmalloc2-20011215
  based on:
  VERSION 2.7.0 Sun Mar 11 14:14:06 2001  Doug Lea  (dl at gee)

* Quickstart

  In order to compile this implementation, a Makefile is provided with
  the ptmalloc2 distribution, which has pre-defined targets for some
  popular systems (e.g. "make posix" for Posix threads).  All that is
  typically required with regard to compiler flags is the selection of
  the thread package via defining one out of USE_PTHREADS, USE_THR or
  USE_SPROC.  Check the thread-m.h file for what effects this has.
  Many/most systems will additionally require USE_TSD_DATA_HACK to be
  defined, so this is the default for "make posix".

* Why use this malloc?

  This is not the fastest, most space-conserving, most portable, or
  most tunable malloc ever written. However it is among the fastest
  while also being among the most space-conserving, portable and tunable.
  Consistent balance across these factors results in a good general-purpose
  allocator for malloc-intensive programs.

  The main properties of the algorithms are:
  * For large (>= 512 bytes) requests, it is a pure best-fit allocator,
    with ties normally decided via FIFO (i.e. least recently used).
  * For small (<= 64 bytes by default) requests, it is a caching
    allocator, that maintains pools of quickly recycled chunks.
  * In between, and for combinations of large and small requests, it does
    the best it can trying to meet both goals at once.
  * For very large requests (>= 128KB by default), it relies on system
    memory mapping facilities, if supported.

  For a longer but slightly out of date high-level description, see
     http://gee.cs.oswego.edu/dl/html/malloc.html

  You may already by default be using a C library containing a malloc
  that is  based on some version of this malloc (for example in
  linux). You might still want to use the one in this file in order to
  customize settings or to avoid overheads associated with library
  versions.

* Contents, described in more detail in "description of public routines" below.

  Standard (ANSI/SVID/...)  functions:
    malloc(size_t n);
    calloc(size_t n_elements, size_t element_size);
    free(void* p);
    realloc(void* p, size_t n);
    memalign(size_t alignment, size_t n);
    valloc(size_t n);
    mallinfo()
    mallopt(int parameter_number, int parameter_value)

  Additional functions:
    independent_calloc(size_t n_elements, size_t size, void* chunks[]);
    independent_comalloc(size_t n_elements, size_t sizes[], void* chunks[]);
    pvalloc(size_t n);
    cfree(void* p);
    malloc_trim(size_t pad);
    malloc_usable_size(void* p);
    malloc_stats();

* Vital statistics:

  Supported pointer representation:       4 or 8 bytes
  Supported size_t  representation:       4 or 8 bytes
       Note that size_t is allowed to be 4 bytes even if pointers are 8.
       You can adjust this by defining INTERNAL_SIZE_T

  Alignment:                              2 * sizeof(size_t) (default)
       (i.e., 8 byte alignment with 4byte size_t). This suffices for
       nearly all current machines and C compilers. However, you can
       define MALLOC_ALIGNMENT to be wider than this if necessary.

  Minimum overhead per allocated chunk:   4 or 8 bytes
       Each malloced chunk has a hidden word of overhead holding size
       and status information.

  Minimum allocated size: 4-byte ptrs:  16 bytes    (including 4 overhead)
			  8-byte ptrs:  24/32 bytes (including, 4/8 overhead)

       When a chunk is freed, 12 (for 4byte ptrs) or 20 (for 8 byte
       ptrs but 4 byte size) or 24 (for 8/8) additional bytes are
       needed; 4 (8) for a trailing size field and 8 (16) bytes for
       free list pointers. Thus, the minimum allocatable size is
       16/24/32 bytes.

       Even a request for zero bytes (i.e., malloc(0)) returns a
       pointer to something of the minimum allocatable size.

       The maximum overhead wastage (i.e., number of extra bytes
       allocated than were requested in malloc) is less than or equal
       to the minimum size, except for requests >= mmap_threshold that
       are serviced via mmap(), where the worst case wastage is 2 *
       sizeof(size_t) bytes plus the remainder from a system page (the
       minimal mmap unit); typically 4096 or 8192 bytes.

  Maximum allocated size:  4-byte size_t: 2^32 minus about two pages
			   8-byte size_t: 2^64 minus about two pages

       It is assumed that (possibly signed) size_t values suffice to
       represent chunk sizes. `Possibly signed' is due to the fact
       that `size_t' may be defined on a system as either a signed or
       an unsigned type. The ISO C standard says that it must be
       unsigned, but a few systems are known not to adhere to this.
       Additionally, even when size_t is unsigned, sbrk (which is by
       default used to obtain memory from system) accepts signed
       arguments, and may not be able to handle size_t-wide arguments
       with negative sign bit.  Generally, values that would
       appear as negative after accounting for overhead and alignment
       are supported only via mmap(), which does not have this
       limitation.

       Requests for sizes outside the allowed range will perform an optional
       failure action and then return null. (Requests may also
       also fail because a system is out of memory.)

  Thread-safety: thread-safe

  Compliance: I believe it is compliant with the 1997 Single Unix Specification
       Also SVID/XPG, ANSI C, and probably others as well.

* Synopsis of compile-time options:

    People have reported using previous versions of this malloc on all
    versions of Unix, sometimes by tweaking some of the defines
    below. It has been tested most extensively on Solaris and Linux.
    People also report using it in stand-alone embedded systems.

    The implementation is in straight, hand-tuned ANSI C.  It is not
    at all modular. (Sorry!)  It uses a lot of macros.  To be at all
    usable, this code should be compiled using an optimizing compiler
    (for example gcc -O3) that can simplify expressions and control
    paths. (FAQ: some macros import variables as arguments rather than
    declare locals because people reported that some debuggers
    otherwise get confused.)

    OPTION                     DEFAULT VALUE

    Compilation Environment options:

    HAVE_MREMAP                0

    Changing default word sizes:

    INTERNAL_SIZE_T            size_t

    Configuration and functionality options:

    USE_PUBLIC_MALLOC_WRAPPERS NOT defined
    USE_MALLOC_LOCK            NOT defined
    MALLOC_DEBUG               NOT defined
    REALLOC_ZERO_BYTES_FREES   1
    TRIM_FASTBINS              0

    Options for customizing MORECORE:

    MORECORE                   sbrk
    MORECORE_FAILURE           -1
    MORECORE_CONTIGUOUS        1
    MORECORE_CANNOT_TRIM       NOT defined
    MORECORE_CLEARS            1
    MMAP_AS_MORECORE_SIZE      (1024 * 1024)

    Tuning options that are also dynamically changeable via mallopt:

    DEFAULT_MXFAST             64 (for 32bit), 128 (for 64bit)
    DEFAULT_TRIM_THRESHOLD     128 * 1024
    DEFAULT_TOP_PAD            0
    DEFAULT_MMAP_THRESHOLD     128 * 1024
    DEFAULT_MMAP_MAX           65536

    There are several other #defined constants and macros that you
    probably don't want to touch unless you are extending or adapting malloc.  */

/*
  void* is the pointer type that malloc should say it returns
*/

#ifndef void
#define void      void
#endif /*void*/

#include <stddef.h>   /* for size_t */
#include <stdlib.h>   /* for getenv(), abort() */
#include <unistd.h>   /* for __libc_enable_secure */

#include <atomic.h>
#include <_itoa.h>
#include <bits/wordsize.h>
#include <sys/sysinfo.h>

#include <ldsodefs.h>

#include <unistd.h>
#include <stdio.h>    /* needed for malloc_stats */
#include <errno.h>

#include <shlib-compat.h>

/* For uintptr_t.  */
#include <stdint.h>

/* For va_arg, va_start, va_end.  */
#include <stdarg.h>

/* For MIN, MAX, powerof2.  */
#include <sys/param.h>

/* For ALIGN_UP et. al.  */
#include <libc-internal.h>

#include <malloc/malloc-internal.h>

/*
  Debugging:

  Because freed chunks may be overwritten with bookkeeping fields, this
  malloc will often die when freed memory is overwritten by user
  programs.  This can be very effective (albeit in an annoying way)
  in helping track down dangling pointers.

  If you compile with -DMALLOC_DEBUG, a number of assertion checks are
  enabled that will catch more memory errors. You probably won't be
  able to make much sense of the actual assertion errors, but they
  should help you locate incorrectly overwritten memory.  The checking
  is fairly extensive, and will slow down execution
  noticeably. Calling malloc_stats or mallinfo with MALLOC_DEBUG set
  will attempt to check every non-mmapped allocated and free chunk in
  the course of computing the summmaries. (By nature, mmapped regions
  cannot be checked very much automatically.)

  Setting MALLOC_DEBUG may also be helpful if you are trying to modify
  this code. The assertions in the check routines spell out in more
  detail the assumptions and invariants underlying the algorithms.

  Setting MALLOC_DEBUG does NOT provide an automated mechanism for
  checking that all accesses to malloced memory stay within their
  bounds. However, there are several add-ons and adaptations of this
  or other mallocs available that do this.
*/

#ifndef MALLOC_DEBUG
#define MALLOC_DEBUG 0
#endif

#ifdef NDEBUG
# define assert(expr) ((void) 0)
#else
# define assert(expr) \
  ((expr)								      \
   ? ((void) 0)								      \
   : __malloc_assert (#expr, __FILE__, __LINE__, __func__))

extern const char *__progname;

static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
#endif


/*
  REALLOC_ZERO_BYTES_FREES should be set if a call to
  realloc with zero bytes should be the same as a call to free.
  This is required by the C standard. Otherwise, since this malloc
  returns a unique pointer for malloc(0), so does realloc(p, 0).
*/

#ifndef REALLOC_ZERO_BYTES_FREES
#define REALLOC_ZERO_BYTES_FREES 1
#endif

/*
  TRIM_FASTBINS controls whether free() of a very small chunk can
  immediately lead to trimming. Setting to true (1) can reduce memory
  footprint, but will almost always slow down programs that use a lot
  of small chunks.

  Define this only if you are willing to give up some speed to more
  aggressively reduce system-level memory footprint when releasing
  memory in programs that use many small chunks.  You can get
  essentially the same effect by setting MXFAST to 0, but this can
  lead to even greater slowdowns in programs using many small chunks.
  TRIM_FASTBINS is an in-between compile-time option, that disables
  only those chunks bordering topmost memory from being placed in
  fastbins.
*/

#ifndef TRIM_FASTBINS
#define TRIM_FASTBINS  0
#endif


/* Definition for getting more memory from the OS.  */
#define MORECORE         (*__morecore)
#define MORECORE_FAILURE 0
void * __default_morecore (ptrdiff_t);
void *(*__morecore)(ptrdiff_t) = __default_morecore;


#include <string.h>

/*
  MORECORE-related declarations. By default, rely on sbrk
*/


/*
  MORECORE is the name of the routine to call to obtain more memory
  from the system.  See below for general guidance on writing
  alternative MORECORE functions, as well as a version for WIN32 and a
  sample version for pre-OSX macos.
*/

#ifndef MORECORE
#define MORECORE sbrk
#endif

/*
  MORECORE_FAILURE is the value returned upon failure of MORECORE
  as well as mmap. Since it cannot be an otherwise valid memory address,
  and must reflect values of standard sys calls, you probably ought not
  try to redefine it.
*/

#ifndef MORECORE_FAILURE
#define MORECORE_FAILURE (-1)
#endif

/*
  If MORECORE_CONTIGUOUS is true, take advantage of fact that
  consecutive calls to MORECORE with positive arguments always return
  contiguous increasing addresses.  This is true of unix sbrk.  Even
  if not defined, when regions happen to be contiguous, malloc will
  permit allocations spanning regions obtained from different
  calls. But defining this when applicable enables some stronger
  consistency checks and space efficiencies.
*/

#ifndef MORECORE_CONTIGUOUS
#define MORECORE_CONTIGUOUS 1
#endif

/*
  Define MORECORE_CANNOT_TRIM if your version of MORECORE
  cannot release space back to the system when given negative
  arguments. This is generally necessary only if you are using
  a hand-crafted MORECORE function that cannot handle negative arguments.
*/

/* #define MORECORE_CANNOT_TRIM */

/*  MORECORE_CLEARS           (default 1)
     The degree to which the routine mapped to MORECORE zeroes out
     memory: never (0), only for newly allocated space (1) or always
     (2).  The distinction between (1) and (2) is necessary because on
     some systems, if the application first decrements and then
     increments the break value, the contents of the reallocated space
     are unspecified.
 */

#ifndef MORECORE_CLEARS
# define MORECORE_CLEARS 1
#endif


/*
   MMAP_AS_MORECORE_SIZE is the minimum mmap size argument to use if
   sbrk fails, and mmap is used as a backup.  The value must be a
   multiple of page size.  This backup strategy generally applies only
   when systems have "holes" in address space, so sbrk cannot perform
   contiguous expansion, but there is still space available on system.
   On systems for which this is known to be useful (i.e. most linux
   kernels), this occurs only when programs allocate huge amounts of
   memory.  Between this, and the fact that mmap regions tend to be
   limited, the size should be large, to avoid too many mmap calls and
   thus avoid running out of kernel resources.  */

#ifndef MMAP_AS_MORECORE_SIZE
#define MMAP_AS_MORECORE_SIZE (1024 * 1024)
#endif

/*
  Define HAVE_MREMAP to make realloc() use mremap() to re-allocate
  large blocks.
*/

#ifndef HAVE_MREMAP
#define HAVE_MREMAP 0
#endif

/* We may need to support __malloc_initialize_hook for backwards
   compatibility.  */

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_24)
# define HAVE_MALLOC_INIT_HOOK 1
#else
# define HAVE_MALLOC_INIT_HOOK 0
#endif


/*
  This version of malloc supports the standard SVID/XPG mallinfo
  routine that returns a struct containing usage properties and
  statistics. It should work on any SVID/XPG compliant system that has
  a /usr/include/malloc.h defining struct mallinfo. (If you'd like to
  install such a thing yourself, cut out the preliminary declarations
  as described above and below and save them in a malloc.h file. But
  there's no compelling reason to bother to do this.)

  The main declaration needed is the mallinfo struct that is returned
  (by-copy) by mallinfo().  The SVID/XPG malloinfo struct contains a
  bunch of fields that are not even meaningful in this version of
  malloc.  These fields are are instead filled by mallinfo() with
  other numbers that might be of interest.
*/


/* ---------- description of public routines ------------ */

/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.

  If n is zero, malloc returns a minumum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/
void*  __libc_malloc(size_t);
libc_hidden_proto (__libc_malloc)

/*
  free(void* p)
  Releases the chunk of memory pointed to by p, that had been previously
  allocated using malloc or a related routine such as realloc.
  It has no effect if p is null. It can have arbitrary (i.e., bad!)
  effects if p has already been freed.

  Unless disabled (using mallopt), freeing very large spaces will
  when possible, automatically trigger operations that give
  back unused memory to the system, thus reducing program footprint.
*/
void     __libc_free(void*);
libc_hidden_proto (__libc_free)

/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
void*  __libc_calloc(size_t, size_t);

/*
  realloc(void* p, size_t n)
  Returns a pointer to a chunk of size n that contains the same data
  as does chunk p up to the minimum of (n, p's size) bytes, or null
  if no space is available.

  The returned pointer may or may not be the same as p. The algorithm
  prefers extending p when possible, otherwise it employs the
  equivalent of a malloc-copy-free sequence.

  If p is null, realloc is equivalent to malloc.

  If space is not available, realloc returns null, errno is set (if on
  ANSI) and p is NOT freed.

  if n is for fewer bytes than already held by p, the newly unused
  space is lopped off and freed if possible.  Unless the #define
  REALLOC_ZERO_BYTES_FREES is set, realloc with a size argument of
  zero (re)allocates a minimum-sized chunk.

  Large chunks that were internally obtained via mmap will always
  be reallocated using malloc-copy-free sequences unless
  the system supports MREMAP (currently only linux).

  The old unix realloc convention of allowing the last-free'd chunk
  to be used as an argument to realloc is not supported.
*/
void*  __libc_realloc(void*, size_t);
libc_hidden_proto (__libc_realloc)

/*
  memalign(size_t alignment, size_t n);
  Returns a pointer to a newly allocated chunk of n bytes, aligned
  in accord with the alignment argument.

  The alignment argument should be a power of two. If the argument is
  not a power of two, the nearest greater power is used.
  8-byte alignment is guaranteed by normal malloc calls, so don't
  bother calling memalign with an argument of 8 or less.

  Overreliance on memalign is a sure way to fragment space.
*/
void*  __libc_memalign(size_t, size_t);
libc_hidden_proto (__libc_memalign)

/*
  valloc(size_t n);
  Equivalent to memalign(pagesize, n), where pagesize is the page
  size of the system. If the pagesize is unknown, 4096 is used.
*/
void*  __libc_valloc(size_t);



/*
  mallopt(int parameter_number, int parameter_value)
  Sets tunable parameters The format is to provide a
  (parameter-number, parameter-value) pair.  mallopt then sets the
  corresponding parameter to the argument value if it can (i.e., so
  long as the value is meaningful), and returns 1 if successful else
  0.  SVID/XPG/ANSI defines four standard param numbers for mallopt,
  normally defined in malloc.h.  Only one of these (M_MXFAST) is used
  in this malloc. The others (M_NLBLKS, M_GRAIN, M_KEEP) don't apply,
  so setting them has no effect. But this malloc also supports four
  other options in mallopt. See below for details.  Briefly, supported
  parameters are as follows (listed defaults are for "typical"
  configurations).

  Symbol            param #   default    allowed param values
  M_MXFAST          1         64         0-80  (0 disables fastbins)
  M_TRIM_THRESHOLD -1         128*1024   any   (-1U disables trimming)
  M_TOP_PAD        -2         0          any
  M_MMAP_THRESHOLD -3         128*1024   any   (or 0 if no MMAP support)
  M_MMAP_MAX       -4         65536      any   (0 disables use of mmap)
*/
int      __libc_mallopt(int, int);
libc_hidden_proto (__libc_mallopt)


/*
  mallinfo()
  Returns (by copy) a struct containing various summary statistics:

  arena:     current total non-mmapped bytes allocated from system
  ordblks:   the number of free chunks
  smblks:    the number of fastbin blocks (i.e., small chunks that
	       have been freed but not use resused or consolidated)
  hblks:     current number of mmapped regions
  hblkhd:    total bytes held in mmapped regions
  usmblks:   always 0
  fsmblks:   total bytes held in fastbin blocks
  uordblks:  current total allocated space (normal or mmapped)
  fordblks:  total free space
  keepcost:  the maximum number of bytes that could ideally be released
	       back to system via malloc_trim. ("ideally" means that
	       it ignores page restrictions etc.)

  Because these fields are ints, but internal bookkeeping may
  be kept as longs, the reported values may wrap around zero and
  thus be inaccurate.
*/
struct mallinfo __libc_mallinfo(void);


/*
  pvalloc(size_t n);
  Equivalent to valloc(minimum-page-that-holds(n)), that is,
  round up n to nearest pagesize.
 */
void*  __libc_pvalloc(size_t);

/*
  malloc_trim(size_t pad);

  If possible, gives memory back to the system (via negative
  arguments to sbrk) if there is unused memory at the `high' end of
  the malloc pool. You can call this after freeing large blocks of
  memory to potentially reduce the system-level memory requirements
  of a program. However, it cannot guarantee to reduce memory. Under
  some allocation patterns, some large free blocks of memory will be
  locked between two used chunks, so they cannot be given back to
  the system.

  The `pad' argument to malloc_trim represents the amount of free
  trailing space to leave untrimmed. If this argument is zero,
  only the minimum amount of memory to maintain internal data
  structures will be left (one page or less). Non-zero arguments
  can be supplied to maintain enough trailing space to service
  future expected allocations without having to re-obtain memory
  from the system.

  Malloc_trim returns 1 if it actually released any memory, else 0.
  On systems that do not support "negative sbrks", it will always
  return 0.
*/
int      __malloc_trim(size_t);

/*
  malloc_usable_size(void* p);

  Returns the number of bytes you can actually use in
  an allocated chunk, which may be more than you requested (although
  often not) due to alignment and minimum size constraints.
  You can use this many bytes without worrying about
  overwriting other allocated objects. This is not a particularly great
  programming practice. malloc_usable_size can be more useful in
  debugging and assertions, for example:

  p = malloc(n);
  assert(malloc_usable_size(p) >= 256);

*/
size_t   __malloc_usable_size(void*);

/*
  malloc_stats();
  Prints on stderr the amount of space obtained from the system (both
  via sbrk and mmap), the maximum amount (which may be more than
  current if malloc_trim and/or munmap got called), and the current
  number of bytes allocated via malloc (or realloc, etc) but not yet
  freed. Note that this is the number of bytes allocated, not the
  number requested. It will be larger than the number requested
  because of alignment and bookkeeping overhead. Because it includes
  alignment wastage as being in use, this figure may be greater than
  zero even when no user-level chunks are allocated.

  The reported current and maximum system memory can be inaccurate if
  a program makes other calls to system memory allocation functions
  (normally sbrk) outside of malloc.

  malloc_stats prints only the most commonly interesting statistics.
  More information can be obtained by calling mallinfo.

*/
void     __malloc_stats(void);

/*
  malloc_get_state(void);

  Returns the state of all malloc variables in an opaque data
  structure.
*/
void*  __malloc_get_state(void);

/*
  malloc_set_state(void* state);

  Restore the state of all malloc variables from data obtained with
  malloc_get_state().
*/
int      __malloc_set_state(void*);

/*
  posix_memalign(void **memptr, size_t alignment, size_t size);

  POSIX wrapper like memalign(), checking for validity of size.
*/
int      __posix_memalign(void **, size_t, size_t);

/* mallopt tuning options */

/*
  M_MXFAST is the maximum request size used for "fastbins", special bins
  that hold returned chunks without consolidating their spaces. This
  enables future requests for chunks of the same size to be handled
  very quickly, but can increase fragmentation, and thus increase the
  overall memory footprint of a program.

  This malloc manages fastbins very conservatively yet still
  efficiently, so fragmentation is rarely a problem for values less
  than or equal to the default.  The maximum supported value of MXFAST
  is 80. You wouldn't want it any higher than this anyway.  Fastbins
  are designed especially for use with many small structs, objects or
  strings -- the default handles structs/objects/arrays with sizes up
  to 8 4byte fields, or small strings representing words, tokens,
  etc. Using fastbins for larger objects normally worsens
  fragmentation without improving speed.

  M_MXFAST is set in REQUEST size units. It is internally used in
  chunksize units, which adds padding and alignment.  You can reduce
  M_MXFAST to 0 to disable all use of fastbins.  This causes the malloc
  algorithm to be a closer approximation of fifo-best-fit in all cases,
  not just for larger requests, but will generally cause it to be
  slower.
*/


/* M_MXFAST is a standard SVID/XPG tuning option, usually listed in malloc.h */
#ifndef M_MXFAST
#define M_MXFAST            1
#endif

#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST     (64 * SIZE_SZ / 4)
#endif


/*
  M_TRIM_THRESHOLD is the maximum amount of unused top-most memory
  to keep before releasing via malloc_trim in free().

  Automatic trimming is mainly useful in long-lived programs.
  Because trimming via sbrk can be slow on some systems, and can
  sometimes be wasteful (in cases where programs immediately
  afterward allocate more large chunks) the value should be high
  enough so that your overall system performance would improve by
  releasing this much memory.

  The trim threshold and the mmap control parameters (see below)
  can be traded off with one another. Trimming and mmapping are
  two different ways of releasing unused memory back to the
  system. Between these two, it is often possible to keep
  system-level demands of a long-lived program down to a bare
  minimum. For example, in one test suite of sessions measuring
  the XF86 X server on Linux, using a trim threshold of 128K and a
  mmap threshold of 192K led to near-minimal long term resource
  consumption.

  If you are using this malloc in a long-lived program, it should
  pay to experiment with these values.  As a rough guide, you
  might set to a value close to the average size of a process
  (program) running on your system.  Releasing this much memory
  would allow such a process to run in memory.  Generally, it's
  worth it to tune for trimming rather tham memory mapping when a
  program undergoes phases where several large chunks are
  allocated and released in ways that can reuse each other's
  storage, perhaps mixed with phases where there are no such
  chunks at all.  And in well-behaved long-lived programs,
  controlling release of large blocks via trimming versus mapping
  is usually faster.

  However, in most programs, these parameters serve mainly as
  protection against the system-level effects of carrying around
  massive amounts of unneeded memory. Since frequent calls to
  sbrk, mmap, and munmap otherwise degrade performance, the default
  parameters are set to relatively high values that serve only as
  safeguards.

  The trim value It must be greater than page size to have any useful
  effect.  To disable trimming completely, you can set to
  (unsigned long)(-1)

  Trim settings interact with fastbin (MXFAST) settings: Unless
  TRIM_FASTBINS is defined, automatic trimming never takes place upon
  freeing a chunk with size less than or equal to MXFAST. Trimming is
  instead delayed until subsequent freeing of larger chunks. However,
  you can still force an attempted trim by calling malloc_trim.

  Also, trimming is not generally possible in cases where
  the main arena is obtained via mmap.

  Note that the trick some people use of mallocing a huge space and
  then freeing it at program startup, in an attempt to reserve system
  memory, doesn't have the intended effect under automatic trimming,
  since that memory will immediately be returned to the system.
*/

#define M_TRIM_THRESHOLD       -1

#ifndef DEFAULT_TRIM_THRESHOLD
#define DEFAULT_TRIM_THRESHOLD (128 * 1024)
#endif

/*
  M_TOP_PAD is the amount of extra `padding' space to allocate or
  retain whenever sbrk is called. It is used in two ways internally:

  * When sbrk is called to extend the top of the arena to satisfy
  a new malloc request, this much padding is added to the sbrk
  request.

  * When malloc_trim is called automatically from free(),
  it is used as the `pad' argument.

  In both cases, the actual amount of padding is rounded
  so that the end of the arena is always a system page boundary.

  The main reason for using padding is to avoid calling sbrk so
  often. Having even a small pad greatly reduces the likelihood
  that nearly every malloc request during program start-up (or
  after trimming) will invoke sbrk, which needlessly wastes
  time.

  Automatic rounding-up to page-size units is normally sufficient
  to avoid measurable overhead, so the default is 0.  However, in
  systems where sbrk is relatively slow, it can pay to increase
  this value, at the expense of carrying around more memory than
  the program needs.
*/

#define M_TOP_PAD              -2

#ifndef DEFAULT_TOP_PAD
#define DEFAULT_TOP_PAD        (0)
#endif

/*
  MMAP_THRESHOLD_MAX and _MIN are the bounds on the dynamically
  adjusted MMAP_THRESHOLD.
*/

#ifndef DEFAULT_MMAP_THRESHOLD_MIN
#define DEFAULT_MMAP_THRESHOLD_MIN (128 * 1024)
#endif

#ifndef DEFAULT_MMAP_THRESHOLD_MAX
  /* For 32-bit platforms we cannot increase the maximum mmap
     threshold much because it is also the minimum value for the
     maximum heap size and its alignment.  Going above 512k (i.e., 1M
     for new heaps) wastes too much address space.  */
# if __WORDSIZE == 32
#  define DEFAULT_MMAP_THRESHOLD_MAX (512 * 1024)
# else
#  define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
# endif
#endif

/*
  M_MMAP_THRESHOLD is the request size threshold for using mmap()
  to service a request. Requests of at least this size that cannot
  be allocated using already-existing space will be serviced via mmap.
  (If enough normal freed space already exists it is used instead.)

  Using mmap segregates relatively large chunks of memory so that
  they can be individually obtained and released from the host
  system. A request serviced through mmap is never reused by any
  other request (at least not directly; the system may just so
  happen to remap successive requests to the same locations).

  Segregating space in this way has the benefits that:

   1. Mmapped space can ALWAYS be individually released back
      to the system, which helps keep the system level memory
      demands of a long-lived program low.
   2. Mapped memory can never become `locked' between
      other chunks, as can happen with normally allocated chunks, which
      means that even trimming via malloc_trim would not release them.
   3. On some systems with "holes" in address spaces, mmap can obtain
      memory that sbrk cannot.

  However, it has the disadvantages that:

   1. The space cannot be reclaimed, consolidated, and then
      used to service later requests, as happens with normal chunks.
   2. It can lead to more wastage because of mmap page alignment
      requirements
   3. It causes malloc performance to be more dependent on host
      system memory management support routines which may vary in
      implementation quality and may impose arbitrary
      limitations. Generally, servicing a request via normal
      malloc steps is faster than going through a system's mmap.

  The advantages of mmap nearly always outweigh disadvantages for
  "large" chunks, but the value of "large" varies across systems.  The
  default is an empirically derived value that works well in most
  systems.


  Update in 2006:
  The above was written in 2001. Since then the world has changed a lot.
  Memory got bigger. Applications got bigger. The virtual address space
  layout in 32 bit linux changed.

  In the new situation, brk() and mmap space is shared and there are no
  artificial limits on brk size imposed by the kernel. What is more,
  applications have started using transient allocations larger than the
  128Kb as was imagined in 2001.

  The price for mmap is also high now; each time glibc mmaps from the
  kernel, the kernel is forced to zero out the memory it gives to the
  application. Zeroing memory is expensive and eats a lot of cache and
  memory bandwidth. This has nothing to do with the efficiency of the
  virtual memory system, by doing mmap the kernel just has no choice but
  to zero.

  In 2001, the kernel had a maximum size for brk() which was about 800
  megabytes on 32 bit x86, at that point brk() would hit the first
  mmaped shared libaries and couldn't expand anymore. With current 2.6
  kernels, the VA space layout is different and brk() and mmap
  both can span the entire heap at will.

  Rather than using a static threshold for the brk/mmap tradeoff,
  we are now using a simple dynamic one. The goal is still to avoid
  fragmentation. The old goals we kept are
  1) try to get the long lived large allocations to use mmap()
  2) really large allocations should always use mmap()
  and we're adding now:
  3) transient allocations should use brk() to avoid forcing the kernel
     having to zero memory over and over again

  The implementation works with a sliding threshold, which is by default
  limited to go between 128Kb and 32Mb (64Mb for 64 bitmachines) and starts
  out at 128Kb as per the 2001 default.

  This allows us to satisfy requirement 1) under the assumption that long
  lived allocations are made early in the process' lifespan, before it has
  started doing dynamic allocations of the same size (which will
  increase the threshold).

  The upperbound on the threshold satisfies requirement 2)

  The threshold goes up in value when the application frees memory that was
  allocated with the mmap allocator. The idea is that once the application
  starts freeing memory of a certain size, it's highly probable that this is
  a size the application uses for transient allocations. This estimator
  is there to satisfy the new third requirement.

*/

#define M_MMAP_THRESHOLD      -3

#ifndef DEFAULT_MMAP_THRESHOLD
#define DEFAULT_MMAP_THRESHOLD DEFAULT_MMAP_THRESHOLD_MIN
#endif

/*
  M_MMAP_MAX is the maximum number of requests to simultaneously
  service using mmap. This parameter exists because
  some systems have a limited number of internal tables for
  use by mmap, and using more than a few of them may degrade
  performance.

  The default is set to a value that serves only as a safeguard.
  Setting to 0 disables use of mmap for servicing large requests.
*/

#define M_MMAP_MAX             -4

#ifndef DEFAULT_MMAP_MAX
#define DEFAULT_MMAP_MAX       (65536)
#endif

#include <malloc.h>

#ifndef RETURN_ADDRESS
#define RETURN_ADDRESS(X_) (NULL)
#endif

/* On some platforms we can compile internal, not exported functions better.
   Let the environment provide a macro and define it to be empty if it
   is not available.  */
#ifndef internal_function
# define internal_function
#endif

/* Forward declarations.  */
struct malloc_chunk;
typedef struct malloc_chunk* mchunkptr;

/* Internal routines.  */

static void*  _int_malloc(mstate, size_t);
static void     _int_free(mstate, mchunkptr, int);
static void*  _int_realloc(mstate, mchunkptr, INTERNAL_SIZE_T,
			   INTERNAL_SIZE_T);
static void*  _int_memalign(mstate, size_t, size_t);
static void*  _mid_memalign(size_t, size_t, void *);

static void malloc_printerr(int action, const char *str, void *ptr, mstate av);

static void* internal_function mem2mem_check(void *p, size_t sz);
static int internal_function top_check(void);
static void internal_function munmap_chunk(mchunkptr p);
#if HAVE_MREMAP
static mchunkptr internal_function mremap_chunk(mchunkptr p, size_t new_size);
#endif

static void*   malloc_check(size_t sz, const void *caller);
static void      free_check(void* mem, const void *caller);
static void*   realloc_check(void* oldmem, size_t bytes,
			       const void *caller);
static void*   memalign_check(size_t alignment, size_t bytes,
				const void *caller);

/* ------------------ MMAP support ------------------  */


#include <fcntl.h>
#include <sys/mman.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
# define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef MAP_NORESERVE
# define MAP_NORESERVE 0
#endif

#define MMAP(addr, size, prot, flags) \
 __mmap((addr), (size), (prot), (flags)|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)


/*
  -----------------------  Chunk representations -----------------------
*/


/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/

struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};


/*
   malloc_chunk details:

    (The following includes lightly edited explanations by Colin Plumb.)

    Chunks of memory are maintained using a `boundary tag' method as
    described in e.g., Knuth or Standish.  (See the paper by Paul
    Wilson ftp://ftp.cs.utexas.edu/pub/garbage/allocsrv.ps for a
    survey of such techniques.)  Sizes of free chunks are stored both
    in the front of each chunk and at the end.  This makes
    consolidating fragmented chunks into bigger chunks very fast.  The
    size fields also hold bits representing whether chunks are free or
    in use.

    An allocated chunk looks like this:


    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             (size of chunk, but used for application data)    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|1|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Where "chunk" is the front of the chunk for the purpose of most of
    the malloc code, but "mem" is the pointer that is returned to the
    user.  "Nextchunk" is the beginning of the next contiguous chunk.

    Chunks always begin on even word boundaries, so the mem portion
    (which is returned to the user) is also on an even word boundary, and
    thus at least double-word aligned.

    Free chunks are stored in circular doubly-linked lists, and look like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Forward pointer to next chunk in list             |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Back pointer to previous chunk in list            |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Unused space (may be 0 bytes long)                .
	    .                                                               .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|0|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    The P (PREV_INUSE) bit, stored in the unused low-order bit of the
    chunk size (which is always a multiple of two words), is an in-use
    bit for the *previous* chunk.  If that bit is *clear*, then the
    word before the current chunk size contains the previous chunk
    size, and can be used to find the front of the previous chunk.
    The very first chunk allocated always has this bit set,
    preventing access to non-existent (or non-owned) memory. If
    prev_inuse is set for any given chunk, then you CANNOT determine
    the size of the previous chunk, and might even get a memory
    addressing fault when trying to do so.

    The A (NON_MAIN_ARENA) bit is cleared for chunks on the initial,
    main arena, described by the main_arena variable.  When additional
    threads are spawned, each thread receives its own arena (up to a
    configurable limit, after which arenas are reused for multiple
    threads), and the chunks in these arenas have the A bit set.  To
    find the arena for a chunk on such a non-main arena, heap_for_ptr
    performs a bit mask operation and indirection through the ar_ptr
    member of the per-heap header heap_info (see arena.c).

    Note that the `foot' of the current chunk is actually represented
    as the prev_size of the NEXT chunk. This makes it easier to
    deal with alignments etc but can be very confusing when trying
    to extend or adapt this code.

    The three exceptions to all this are:

     1. The special chunk `top' doesn't bother using the
	trailing size field since there is no next contiguous chunk
	that would have to index off it. After initialization, `top'
	is forced to always exist.  If it would become less than
	MINSIZE bytes long, it is replenished.

     2. Chunks allocated via mmap, which have the second-lowest-order
	bit M (IS_MMAPPED) set in their size fields.  Because they are
	allocated one-by-one, each must contain its own trailing size
	field.  If the M bit is set, the other bits are ignored
	(because mmapped chunks are neither in an arena, nor adjacent
	to a freed chunk).  The M bit is also used for chunks which
	originally came from a dumped heap via malloc_set_state in
	hooks.c.

     3. Chunks in fastbins are treated as allocated chunks from the
	point of view of the chunk allocator.  They are consolidated
	with their neighbors only in bulk, in malloc_consolidate.
*/

/*
  ---------- Size and alignment checks and conversions ----------
*/

/* conversion from malloc headers to user pointers, and back */

#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

/* Check if m has acceptable alignment */

#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)


/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=						      \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))

/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                             \
  if (REQUEST_OUT_OF_RANGE (req)) {					      \
      __set_errno (ENOMEM);						      \
      return 0;								      \
    }									      \
  (sz) = request2size (req);

/*
   --------------- Physical chunk operations ---------------
 */


/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->mchunk_size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)


/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* Check for chunk from main arena.  */
#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)

/* Mark a chunk as not being on the main arena.  */
#define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)


/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + chunksize (p)))

/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Set the size of the chunk below P.  Only valid if prev_inuse (P).  */
#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))

/* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - prev_size (p)))

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

/* extract p's inuse bit */
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size |= PREV_INUSE

#define clear_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size &= ~(PREV_INUSE)


  /* check/set/clear inuse bits in known places */
  #define inuse_bit_at_offset(p, s)					      \
    (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

  #define set_inuse_bit_at_offset(p, s)					      \
    (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

  #define clear_inuse_bit_at_offset(p, s)					      \
    (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))


/* Set size at head, without disturbing its use bit */
#define set_head_size(p, s)  ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s)       ((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))


#pragma GCC poison mchunk_size
#pragma GCC poison mchunk_prev_size

/*
   -------------------- Internal data structures --------------------

   All internal state is held in an instance of malloc_state defined
   below. There are no other static variables, except in two optional
   cases:
 * If USE_MALLOC_LOCK is defined, the mALLOC_MUTEx declared above.
 * If mmap doesn't support MAP_ANONYMOUS, a dummy file descriptor
     for mmap.

   Beware of lots of tricks that minimize the total bookkeeping space
   requirements. The result is a little over 1K bytes (for 4byte
   pointers and size_t.)
 */

/*
   Bins

    An array of bin headers for free chunks. Each bin is doubly
    linked.  The bins are approximately proportionally (log) spaced.
    There are a lot of these bins (128). This may look excessive, but
    works very well in practice.  Most bins hold sizes that are
    unusual as malloc request sizes, but are more usual for fragments
    and consolidated sets of chunks, which is what these bins hold, so
    they can be found quickly.  All procedures maintain the invariant
    that no consolidated chunk physically borders another one, so each
    chunk in a list is known to be preceeded and followed by either
    inuse chunks or the ends of memory.

    Chunks in bins are kept in size order, with ties going to the
    approximately least recently used chunk. Ordering isn't needed
    for the small bins, which all contain the same-sized chunks, but
    facilitates best-fit allocation for larger chunks. These lists
    are just sequential. Keeping them in order almost never requires
    enough traversal to warrant using fancier ordered data
    structures.

    Chunks of the same size are linked with the most
    recently freed at the front, and allocations are taken from the
    back.  This results in LRU (FIFO) allocation order, which tends
    to give each chunk an equal opportunity to be consolidated with
    adjacent freed chunks, resulting in larger free chunks and less
    fragmentation.

    To simplify use in double-linked lists, each bin header acts
    as a malloc_chunk. This avoids special-casing for headers.
    But to conserve space and improve locality, we allocate
    only the fd/bk pointers of bins, and then use repositioning tricks
    to treat these as the fields of a malloc_chunk*.
 */

typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))			      \
             - offsetof (struct malloc_chunk, fd))

/* analog of ++bin */
#define next_bin(b)  ((mbinptr) ((char *) (b) + (sizeof (mchunkptr) << 1)))

/* Reminders about list directionality within bins */
#define first(b)     ((b)->fd)
#define last(b)      ((b)->bk)

/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (chunksize_nomask (P))			      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}

/*
   Indexing

    Bins for sizes < 512 bytes contain chunks of all the same size, spaced
    8 bytes apart. Larger bins are approximately logarithmically spaced:

    64 bins of size       8
    32 bins of size      64
    16 bins of size     512
     8 bins of size    4096
     4 bins of size   32768
     2 bins of size  262144
     1 bin  of size what's left

    There is actually a little bit of slop in the numbers in bin_index
    for the sake of speed. This makes no difference elsewhere.

    The bins top out around 1MB because we expect to service large
    requests via mmap.

    Bin 0 does not exist.  Bin 1 is the unordered list; if that would be
    a valid chunk size the small bins are bumped up one.
 */

#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)

#define largebin_index_32(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 38) ?  56 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index_32_big(sz)                                            \
  (((((unsigned long) (sz)) >> 6) <= 45) ?  49 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))

#define bin_index(sz) \
  ((in_smallbin_range (sz)) ? smallbin_index (sz) : largebin_index (sz))


/*
   Unsorted chunks

    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free (and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.

    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
 */

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M)          (bin_at (M, 1))

/*
   Top

    The top-most available chunk (i.e., the one bordering the end of
    available memory) is treated specially. It is never included in
    any bin, is used only if no other chunk is available, and is
    released back to the system if it is very large (see
    M_TRIM_THRESHOLD).  Because top initially
    points to its own bin with initial zero size, thus forcing
    extension on the first malloc request, we avoid having any special
    code in malloc to check whether it even exists yet. But we still
    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the
    interval between initialization and the first call to
    sysmalloc. (This is somewhat delicate, since it relies on
    the 2 preceding words to be zero during this interval as well.)
 */

/* Conveniently, the unsorted bin can be used as dummy top on first call */
#define initial_top(M)              (unsorted_chunks (M))

/*
   Binmap

    To help compensate for the large number of bins, a one-level index
    structure is used for bin-by-bin searching.  `binmap' is a
    bitvector recording whether bins are definitely empty so they can
    be skipped over during during traversals.  The bits are NOT always
    cleared as soon as bins are empty, but instead only
    when they are noticed to be empty during traversal in malloc.
    많은 수의 bins를 보완하기 위해서 one-level index 구조체가 bin-by-bin 검색을 하는데에 사용된다. `binmap`은 bins가 분명하게 empty한 상태인지 여부를 기록하는 bitvector이다. 따라서, bins 검색 중에 몇 몇 bins를 건너뛸 수 있다.
    bits는 bins가 empty할 때마다 바로 지워지지는 않지만, 대신 malloc 동작 중 검색하는 과정에서 empty하다고 인식되는 경우에만 지워진다.
 */

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP)

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

#define mark_bin(m, i)    ((m)->binmap[idx2block (i)] |= idx2bit (i))
#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))

/*
   Fastbins

    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.

    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */

typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)


/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)

#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)

/*
   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
   that triggers automatic consolidation of possibly-surrounding
   fastbin chunks. This is a heuristic, so the exact value should not
   matter too much. It is defined at half the default trim threshold as a
   compromise heuristic to only attempt consolidation if it is likely
   to lead to trimming. However, it is not dynamically tunable, since
   consolidation reduces fragmentation surrounding large chunks even
   if trimming is not used.
 */

#define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)

/*
   Since the lowest 2 bits in max_fast don't matter in size comparisons,
   they are used as flags.
 */

/*
   FASTCHUNKS_BIT held in max_fast indicates that there are probably
   some fastbin chunks. It is set true on entering a chunk into any
   fastbin, and cleared only in malloc_consolidate.

   The truth value is inverted so that have_fastchunks will be true
   upon startup (since statics are zero-filled), simplifying
   initialization checks.
 */

#define FASTCHUNKS_BIT        (1U)

#define have_fastchunks(M)     (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M)    catomic_or (&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M)      catomic_and (&(M)->flags, ~FASTCHUNKS_BIT)

/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.

   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */

#define NONCONTIGUOUS_BIT     (2U)

#define contiguous(M)          (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M)       (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M)   ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M)      ((M)->flags &= ~NONCONTIGUOUS_BIT)

/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
   arena.  Such an arena is no longer used to allocate chunks.  Chunks
   allocated in that arena before detecting corruption are not freed.  */

#define ARENA_CORRUPTION_BIT (4U)

#define arena_is_corrupt(A)	(((A)->flags & ARENA_CORRUPTION_BIT))
#define set_arena_corrupt(A)	((A)->flags |= ARENA_CORRUPTION_BIT)

/*
   Set value of max_fast.
   Use impossibly small value if 0.
   Precondition: there are no existing fastbin chunks.
   Setting the value clears fastchunk bit but preserves noncontiguous bit.
 */

#define set_max_fast(s) \
  global_max_fast = (((s) == 0)						      \
                     ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
#define get_max_fast() global_max_fast


/*
   ----------- Internal state representation and initialization -----------
 */

struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

struct malloc_par
{
  /* Tunable parameters */
  unsigned long trim_threshold;
  INTERNAL_SIZE_T top_pad;
  INTERNAL_SIZE_T mmap_threshold;
  INTERNAL_SIZE_T arena_test;
  INTERNAL_SIZE_T arena_max;

  /* Memory map support */
  int n_mmaps;
  int n_mmaps_max;
  int max_n_mmaps;
  /* the mmap_threshold is dynamic, until the user sets
     it manually, at which point we need to disable any
     dynamic behavior. */
  int no_dyn_threshold;

  /* Statistics */
  INTERNAL_SIZE_T mmapped_mem;
  INTERNAL_SIZE_T max_mmapped_mem;

  /* First address handed out by MORECORE/sbrk.  */
  char *sbrk_base;
};

/* There are several instances of this struct ("arenas") in this
   malloc.  If you are adapting this malloc in a way that does NOT use
   a static or mmapped malloc_state, you MUST explicitly zero-fill it
   before using. This malloc relies on the property that malloc_state
   is initialized to all zeroes (as is true of C statics).  */

static struct malloc_state main_arena =
{
  .mutex = _LIBC_LOCK_INITIALIZER,
  .next = &main_arena,
  .attached_threads = 1
};

/* These variables are used for undumping support.  Chunked are marked
   as using mmap, but we leave them alone if they fall into this
   range.  NB: The chunk size for these chunks only includes the
   initial size field (of SIZE_SZ bytes), there is no trailing size
   field (unlike with regular mmapped chunks).  */
static mchunkptr dumped_main_arena_start; /* Inclusive.  */
static mchunkptr dumped_main_arena_end;   /* Exclusive.  */

/* True if the pointer falls into the dumped arena.  Use this after
   chunk_is_mmapped indicates a chunk is mmapped.  */
#define DUMPED_MAIN_ARENA_CHUNK(p) \
  ((p) >= dumped_main_arena_start && (p) < dumped_main_arena_end)

/* There is only one instance of the malloc parameters.  */

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
};

/* Maximum size of memory handled in fastbins.  */
static INTERNAL_SIZE_T global_max_fast;

/*
   Initialize a malloc_state struct.

   This is called only from within malloc_consolidate, which needs
   be called in the same contexts anyway.  It is never called directly
   outside of malloc_consolidate because some optimizing compilers try
   to inline it at all call points, which turns out not to be an
   optimization at all. (Inlining it in malloc_consolidate is fine though.)
 */

static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  for (i = 1; i < NBINS; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
    }

#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
  set_noncontiguous (av);
  if (av == &main_arena)
    set_max_fast (DEFAULT_MXFAST);
  av->flags |= FASTCHUNKS_BIT;

  av->top = initial_top (av);
}

/*
   Other internal utilities operating on mstates
 */

static void *sysmalloc (INTERNAL_SIZE_T, mstate);
static int      systrim (size_t, mstate);
static void     malloc_consolidate (mstate);


/* -------------- Early definitions for debugging hooks ---------------- */

/* Define and initialize the hook variables.  These weak definitions must
   appear before any use of the variables in a function (arena.c uses one).  */
#ifndef weak_variable
/* In GNU libc we want the hook variables to be weak definitions to
   avoid a problem with Emacs.  */
# define weak_variable weak_function
#endif

/* Forward declarations.  */
static void *malloc_hook_ini (size_t sz,
                              const void *caller) __THROW;
static void *realloc_hook_ini (void *ptr, size_t sz,
                               const void *caller) __THROW;
static void *memalign_hook_ini (size_t alignment, size_t sz,
                                const void *caller) __THROW;

#if HAVE_MALLOC_INIT_HOOK
void weak_variable (*__malloc_initialize_hook) (void) = NULL;
compat_symbol (libc, __malloc_initialize_hook,
	       __malloc_initialize_hook, GLIBC_2_0);
#endif

void weak_variable (*__free_hook) (void *__ptr,
                                   const void *) = NULL;
void *weak_variable (*__malloc_hook)
  (size_t __size, const void *) = malloc_hook_ini;
void *weak_variable (*__realloc_hook)
  (void *__ptr, size_t __size, const void *)
  = realloc_hook_ini;
void *weak_variable (*__memalign_hook)
  (size_t __alignment, size_t __size, const void *)
  = memalign_hook_ini;
void weak_variable (*__after_morecore_hook) (void) = NULL;


/* ---------------- Error behavior ------------------------------------ */

#ifndef DEFAULT_CHECK_ACTION
# define DEFAULT_CHECK_ACTION 3
#endif

static int check_action = DEFAULT_CHECK_ACTION;


/* ------------------ Testing support ----------------------------------*/

static int perturb_byte;

static void
alloc_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))
    memset (p, perturb_byte ^ 0xff, n);
}

static void
free_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))
    memset (p, perturb_byte, n);
}



#include <stap-probe.h>

/* ------------------- Support for multiple arenas -------------------- */
#include "arena.c"

/*
   Debugging support

   These routines make a number of assertions about the states
   of data structures that should be true at all times. If any
   are not true, it's very likely that a user program has somehow
   trashed memory. (It's also possible that there is a coding error
   in malloc. In which case, please report it!)
 */

#if !MALLOC_DEBUG

# define check_chunk(A, P)
# define check_free_chunk(A, P)
# define check_inuse_chunk(A, P)
# define check_remalloced_chunk(A, P, N)
# define check_malloced_chunk(A, P, N)
# define check_malloc_state(A)

#else

# define check_chunk(A, P)              do_check_chunk (A, P)
# define check_free_chunk(A, P)         do_check_free_chunk (A, P)
# define check_inuse_chunk(A, P)        do_check_inuse_chunk (A, P)
# define check_remalloced_chunk(A, P, N) do_check_remalloced_chunk (A, P, N)
# define check_malloced_chunk(A, P, N)   do_check_malloced_chunk (A, P, N)
# define check_malloc_state(A)         do_check_malloc_state (A)

/*
   Properties of all chunks
 */

static void
do_check_chunk (mstate av, mchunkptr p)
{
  unsigned long sz = chunksize (p);
  /* min and max possible addresses assuming contiguous allocation */
  char *max_address = (char *) (av->top) + chunksize (av->top);
  char *min_address = max_address - av->system_mem;

  if (!chunk_is_mmapped (p))
    {
      /* Has legal address ... */
      if (p != av->top)
        {
          if (contiguous (av))
            {
              assert (((char *) p) >= min_address);
              assert (((char *) p + sz) <= ((char *) (av->top)));
            }
        }
      else
        {
          /* top size is always at least MINSIZE */
          assert ((unsigned long) (sz) >= MINSIZE);
          /* top predecessor always marked inuse */
          assert (prev_inuse (p));
        }
    }
  else if (!DUMPED_MAIN_ARENA_CHUNK (p))
    {
      /* address is outside main heap  */
      if (contiguous (av) && av->top != initial_top (av))
        {
          assert (((char *) p) < min_address || ((char *) p) >= max_address);
        }
      /* chunk is page-aligned */
      assert (((prev_size (p) + sz) & (GLRO (dl_pagesize) - 1)) == 0);
      /* mem is aligned */
      assert (aligned_OK (chunk2mem (p)));
    }
}

/*
   Properties of free chunks
 */

static void
do_check_free_chunk (mstate av, mchunkptr p)
{
  INTERNAL_SIZE_T sz = p->size & ~(PREV_INUSE | NON_MAIN_ARENA);
  mchunkptr next = chunk_at_offset (p, sz);

  do_check_chunk (av, p);

  /* Chunk must claim to be free ... */
  assert (!inuse (p));
  assert (!chunk_is_mmapped (p));

  /* Unless a special marker, must have OK fields */
  if ((unsigned long) (sz) >= MINSIZE)
    {
      assert ((sz & MALLOC_ALIGN_MASK) == 0);
      assert (aligned_OK (chunk2mem (p)));
      /* ... matching footer field */
      assert (prev_size (p) == sz);
      /* ... and is fully consolidated */
      assert (prev_inuse (p));
      assert (next == av->top || inuse (next));

      /* ... and has minimally sane links */
      assert (p->fd->bk == p);
      assert (p->bk->fd == p);
    }
  else /* markers are always of size SIZE_SZ */
    assert (sz == SIZE_SZ);
}

/*
   Properties of inuse chunks
 */

static void
do_check_inuse_chunk (mstate av, mchunkptr p)
{
  mchunkptr next;

  do_check_chunk (av, p);

  if (chunk_is_mmapped (p))
    return; /* mmapped chunks have no next/prev */

  /* Check whether it claims to be in use ... */
  assert (inuse (p));

  next = next_chunk (p);

  /* ... and is surrounded by OK chunks.
     Since more things can be checked with free chunks than inuse ones,
     if an inuse chunk borders them and debug is on, it's worth doing them.
   */
  if (!prev_inuse (p))
    {
      /* Note that we cannot even look at prev unless it is not inuse */
      mchunkptr prv = prev_chunk (p);
      assert (next_chunk (prv) == p);
      do_check_free_chunk (av, prv);
    }

  if (next == av->top)
    {
      assert (prev_inuse (next));
      assert (chunksize (next) >= MINSIZE);
    }
  else if (!inuse (next))
    do_check_free_chunk (av, next);
}

/*
   Properties of chunks recycled from fastbins
 */

static void
do_check_remalloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
{
  INTERNAL_SIZE_T sz = p->size & ~(PREV_INUSE | NON_MAIN_ARENA);

  if (!chunk_is_mmapped (p))
    {
      assert (av == arena_for_chunk (p));
      if (chunk_main_arena (p))
        assert (av == &main_arena);
      else
        assert (av != &main_arena);
    }

  do_check_inuse_chunk (av, p);

  /* Legal size ... */
  assert ((sz & MALLOC_ALIGN_MASK) == 0);
  assert ((unsigned long) (sz) >= MINSIZE);
  /* ... and alignment */
  assert (aligned_OK (chunk2mem (p)));
  /* chunk is less than MINSIZE more than request */
  assert ((long) (sz) - (long) (s) >= 0);
  assert ((long) (sz) - (long) (s + MINSIZE) < 0);
}

/*
   Properties of nonrecycled chunks at the point they are malloced
 */

static void
do_check_malloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
{
  /* same as recycled case ... */
  do_check_remalloced_chunk (av, p, s);

  /*
     ... plus,  must obey implementation invariant that prev_inuse is
     always true of any allocated chunk; i.e., that each allocated
     chunk borders either a previously allocated and still in-use
     chunk, or the base of its memory arena. This is ensured
     by making all allocations from the `lowest' part of any found
     chunk.  This does not necessarily hold however for chunks
     recycled via fastbins.
   */

  assert (prev_inuse (p));
}


/*
   Properties of malloc_state.

   This may be useful for debugging malloc, as well as detecting user
   programmer errors that somehow write into malloc_state.

   If you are extending or experimenting with this malloc, you can
   probably figure out how to hack this routine to print out or
   display chunk addresses, sizes, bins, and other instrumentation.
 */

static void
do_check_malloc_state (mstate av)
{
  int i;
  mchunkptr p;
  mchunkptr q;
  mbinptr b;
  unsigned int idx;
  INTERNAL_SIZE_T size;
  unsigned long total = 0;
  int max_fast_bin;

  /* internal size_t must be no wider than pointer type */
  assert (sizeof (INTERNAL_SIZE_T) <= sizeof (char *));

  /* alignment is a power of 2 */
  assert ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT - 1)) == 0);

  /* cannot run remaining checks until fully initialized */
  if (av->top == 0 || av->top == initial_top (av))
    return;

  /* pagesize is a power of 2 */
  assert (powerof2(GLRO (dl_pagesize)));

  /* A contiguous main_arena is consistent with sbrk_base.  */
  if (av == &main_arena && contiguous (av))
    assert ((char *) mp_.sbrk_base + av->system_mem ==
            (char *) av->top + chunksize (av->top));

  /* properties of fastbins */

  /* max_fast is in allowed range */
  assert ((get_max_fast () & ~1) <= request2size (MAX_FAST_SIZE));

  max_fast_bin = fastbin_index (get_max_fast ());

  for (i = 0; i < NFASTBINS; ++i)
    {
      p = fastbin (av, i);

      /* The following test can only be performed for the main arena.
         While mallopt calls malloc_consolidate to get rid of all fast
         bins (especially those larger than the new maximum) this does
         only happen for the main arena.  Trying to do this for any
         other arena would mean those arenas have to be locked and
         malloc_consolidate be called for them.  This is excessive.  And
         even if this is acceptable to somebody it still cannot solve
         the problem completely since if the arena is locked a
         concurrent malloc call might create a new arena which then
         could use the newly invalid fast bins.  */

      /* all bins past max_fast are empty */
      if (av == &main_arena && i > max_fast_bin)
        assert (p == 0);

      while (p != 0)
        {
          /* each chunk claims to be inuse */
          do_check_inuse_chunk (av, p);
          total += chunksize (p);
          /* chunk belongs in this bin */
          assert (fastbin_index (chunksize (p)) == i);
          p = p->fd;
        }
    }

  if (total != 0)
    assert (have_fastchunks (av));
  else if (!have_fastchunks (av))
    assert (total == 0);

  /* check normal bins */
  for (i = 1; i < NBINS; ++i)
    {
      b = bin_at (av, i);

      /* binmap is accurate (except for bin 1 == unsorted_chunks) */
      if (i >= 2)
        {
          unsigned int binbit = get_binmap (av, i);
          int empty = last (b) == b;
          if (!binbit)
            assert (empty);
          else if (!empty)
            assert (binbit);
        }

      for (p = last (b); p != b; p = p->bk)
        {
          /* each chunk claims to be free */
          do_check_free_chunk (av, p);
          size = chunksize (p);
          total += size;
          if (i >= 2)
            {
              /* chunk belongs in bin */
              idx = bin_index (size);
              assert (idx == i);
              /* lists are sorted */
              assert (p->bk == b ||
                      (unsigned long) chunksize (p->bk) >= (unsigned long) chunksize (p));

              if (!in_smallbin_range (size))
                {
                  if (p->fd_nextsize != NULL)
                    {
                      if (p->fd_nextsize == p)
                        assert (p->bk_nextsize == p);
                      else
                        {
                          if (p->fd_nextsize == first (b))
                            assert (chunksize (p) < chunksize (p->fd_nextsize));
                          else
                            assert (chunksize (p) > chunksize (p->fd_nextsize));

                          if (p == first (b))
                            assert (chunksize (p) > chunksize (p->bk_nextsize));
                          else
                            assert (chunksize (p) < chunksize (p->bk_nextsize));
                        }
                    }
                  else
                    assert (p->bk_nextsize == NULL);
                }
            }
          else if (!in_smallbin_range (size))
            assert (p->fd_nextsize == NULL && p->bk_nextsize == NULL);
          /* chunk is followed by a legal chain of inuse chunks */
          for (q = next_chunk (p);
               (q != av->top && inuse (q) &&
                (unsigned long) (chunksize (q)) >= MINSIZE);
               q = next_chunk (q))
            do_check_inuse_chunk (av, q);
        }
    }

  /* top chunk is OK */
  check_chunk (av, av->top);
}
#endif


/* ----------------- Support for debugging hooks -------------------- */
#include "hooks.c"


/* ----------- Routines dealing with system allocation -------------- */

/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */

static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* incoming value of av->top */
  INTERNAL_SIZE_T old_size;       /* its size */
  char *old_end;                  /* its end address */

  long size;                      /* arg to first MORECORE or mmap call */
  char *brk;                      /* return value from MORECORE */

  long correction;                /* arg to 2nd MORECORE call */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                    /* the allocated/returned chunk */
  mchunkptr remainder;            /* remainder from allocation */
  unsigned long remainder_size;   /* its size */


  size_t pagesize = GLRO (dl_pagesize);
  bool tried_mmap = false;


  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */

  if (av == NULL
      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
	  && (mp_.n_mmaps < mp_.n_mmaps_max)))
    {
      char *mm;           /* return value from mmap call*/

    try_mmap:
      /*
         Round up size to nearest page.  For mmapped chunks, the overhead
         is one SIZE_SZ unit larger than for normal chunks, because there
         is no following chunk whose prev_size field could be used.

         See the front_misalign handling below, for glibc there is no
         need for further alignments unless we have have high alignment.
       */
      if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
        size = ALIGN_UP (nb + SIZE_SZ, pagesize);
      else
        size = ALIGN_UP (nb + SIZE_SZ + MALLOC_ALIGN_MASK, pagesize);
      tried_mmap = true;

      /* Don't try if size wraps around 0 */
      if ((unsigned long) (size) > (unsigned long) (nb))
        {
          mm = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));

          if (mm != MAP_FAILED)
            {
              /*
                 The offset to the start of the mmapped region is stored
                 in the prev_size field of the chunk. This allows us to adjust
                 returned start address to meet alignment requirements here
                 and in memalign(), and still be able to compute proper
                 address argument for later munmap in free() and realloc().
               */

              if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
                {
                  /* For glibc, chunk2mem increases the address by 2*SIZE_SZ and
                     MALLOC_ALIGN_MASK is 2*SIZE_SZ-1.  Each mmap'ed area is page
                     aligned and therefore definitely MALLOC_ALIGN_MASK-aligned.  */
                  assert (((INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK) == 0);
                  front_misalign = 0;
                }
              else
                front_misalign = (INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK;
              if (front_misalign > 0)
                {
                  correction = MALLOC_ALIGNMENT - front_misalign;
                  p = (mchunkptr) (mm + correction);
		  set_prev_size (p, correction);
                  set_head (p, (size - correction) | IS_MMAPPED);
                }
              else
                {
                  p = (mchunkptr) mm;
		  set_prev_size (p, 0);
                  set_head (p, size | IS_MMAPPED);
                }

              /* update statistics */

              int new = atomic_exchange_and_add (&mp_.n_mmaps, 1) + 1;
              atomic_max (&mp_.max_n_mmaps, new);

              unsigned long sum;
              sum = atomic_exchange_and_add (&mp_.mmapped_mem, size) + size;
              atomic_max (&mp_.max_mmapped_mem, sum);

              check_chunk (av, p);

              return chunk2mem (p);
            }
        }
    }

  /* There are no usable arenas and mmap also failed.  */
  if (av == NULL)
    return 0;

  /* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));

  brk = snd_brk = (char *) (MORECORE_FAILURE);

  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));


  if (av != &main_arena)
    {
      heap_info *old_heap, *heap;
      size_t old_heap_size;

      /* First try to extend the current heap. */
      old_heap = heap_for_ptr (old_top);
      old_heap_size = old_heap->size;
      if ((long) (MINSIZE + nb - old_size) > 0
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
        {
          av->system_mem += old_heap->size - old_heap_size;
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE);
        }
      else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))
        {
          /* Use a newly allocated heap.  */
          heap->ar_ptr = av;
          heap->prev = old_heap;
          av->system_mem += heap->size;
          /* Set up the new top.  */
          top (av) = chunk_at_offset (heap, sizeof (*heap));
          set_head (top (av), (heap->size - sizeof (*heap)) | PREV_INUSE);

          /* Setup fencepost and free the old top chunk with a multiple of
             MALLOC_ALIGNMENT in size. */
          /* The fencepost takes at least MINSIZE bytes, because it might
             become the top chunk again later.  Note that a footer is set
             up, too, although the chunk is marked in use. */
          old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
          set_head (chunk_at_offset (old_top, old_size + 2 * SIZE_SZ), 0 | PREV_INUSE);
          if (old_size >= MINSIZE)
            {
              set_head (chunk_at_offset (old_top, old_size), (2 * SIZE_SZ) | PREV_INUSE);
              set_foot (chunk_at_offset (old_top, old_size), (2 * SIZE_SZ));
              set_head (old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
              _int_free (av, old_top, 1);
            }
          else
            {
              set_head (old_top, (old_size + 2 * SIZE_SZ) | PREV_INUSE);
              set_foot (old_top, (old_size + 2 * SIZE_SZ));
            }
        }
      else if (!tried_mmap)
        /* We can at least try to use to mmap memory.  */
        goto try_mmap;
    }
  else     /* av == main_arena */


    { /* Request enough space for nb + pad + overhead */
      size = nb + mp_.top_pad + MINSIZE;

      /*
         If contiguous, we can subtract out existing space that we hope to
         combine with new space. We add it back later only if
         we don't actually get contiguous space.
       */

      if (contiguous (av))
        size -= old_size;

      /*
         Round to a multiple of page size.
         If MORECORE is not contiguous, this ensures that we only call it
         with whole-page arguments.  And if MORECORE is contiguous and
         this is not first time through, this preserves page-alignment of
         previous calls. Otherwise, we correct to page-align below.
       */

      size = ALIGN_UP (size, pagesize);

      /*
         Don't try to call MORECORE if argument is so big as to appear
         negative. Note that since mmap takes size_t arg, it may succeed
         below even if we cannot call MORECORE.
       */

      if (size > 0)
        {
          brk = (char *) (MORECORE (size));
          LIBC_PROBE (memory_sbrk_more, 2, brk, size);
        }

      if (brk != (char *) (MORECORE_FAILURE))
        {
          /* Call the `morecore' hook if necessary.  */
          void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
          if (__builtin_expect (hook != NULL, 0))
            (*hook)();
        }
      else
        {
          /*
             If have mmap, try using it as a backup when MORECORE fails or
             cannot be used. This is worth doing on systems that have "holes" in
             address space, so sbrk cannot extend to give contiguous space, but
             space is available elsewhere.  Note that we ignore mmap max count
             and threshold limits, since the space will not be used as a
             segregated mmap region.
           */

          /* Cannot merge with old top, so add its size back in */
          if (contiguous (av))
            size = ALIGN_UP (size + old_size, pagesize);

          /* If we are relying on mmap as backup, then use larger units */
          if ((unsigned long) (size) < (unsigned long) (MMAP_AS_MORECORE_SIZE))
            size = MMAP_AS_MORECORE_SIZE;

          /* Don't try if size wraps around 0 */
          if ((unsigned long) (size) > (unsigned long) (nb))
            {
              char *mbrk = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));

              if (mbrk != MAP_FAILED)
                {
                  /* We do not need, and cannot use, another sbrk call to find end */
                  brk = mbrk;
                  snd_brk = brk + size;

                  /*
                     Record that we no longer have a contiguous sbrk region.
                     After the first time mmap is used as backup, we do not
                     ever rely on contiguous space since this could incorrectly
                     bridge regions.
                   */
                  set_noncontiguous (av);
                }
            }
        }

      if (brk != (char *) (MORECORE_FAILURE))
        {
          if (mp_.sbrk_base == 0)
            mp_.sbrk_base = brk;
          av->system_mem += size;

          /*
             If MORECORE extends previous space, we can likewise extend top size.
           */

          if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE))
            set_head (old_top, (size + old_size) | PREV_INUSE);

          else if (contiguous (av) && old_size && brk < old_end)
            {
              /* Oops!  Someone else killed our space..  Can't touch anything.  */
              malloc_printerr (3, "break adjusted to free malloc space", brk,
			       av);
            }

          /*
             Otherwise, make adjustments:

           * If the first time through or noncontiguous, we need to call sbrk
              just to find out where the end of memory lies.

           * We need to ensure that all returned chunks from malloc will meet
              MALLOC_ALIGNMENT

           * If there was an intervening foreign sbrk, we need to adjust sbrk
              request size to account for fact that we will not be able to
              combine new space with existing space in old_top.

           * Almost all systems internally allocate whole pages at a time, in
              which case we might as well use the whole last page of request.
              So we allocate enough more memory to hit a page boundary now,
              which in turn causes future contiguous calls to page-align.
           */

          else
            {
              front_misalign = 0;
              end_misalign = 0;
              correction = 0;
              aligned_brk = brk;

              /* handle contiguous cases */
              if (contiguous (av))
                {
                  /* Count foreign sbrk as system_mem.  */
                  if (old_size)
                    av->system_mem += brk - old_end;

                  /* Guarantee alignment of first new chunk made from this space */

                  front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                  if (front_misalign > 0)
                    {
                      /*
                         Skip over some bytes to arrive at an aligned position.
                         We don't need to specially mark these wasted front bytes.
                         They will never be accessed anyway because
                         prev_inuse of av->top (and any chunk created from its start)
                         is always true after initialization.
                       */

                      correction = MALLOC_ALIGNMENT - front_misalign;
                      aligned_brk += correction;
                    }

                  /*
                     If this isn't adjacent to existing space, then we will not
                     be able to merge with old_top space, so must add to 2nd request.
                   */

                  correction += old_size;

                  /* Extend the end address to hit a page boundary */
                  end_misalign = (INTERNAL_SIZE_T) (brk + size + correction);
                  correction += (ALIGN_UP (end_misalign, pagesize)) - end_misalign;

                  assert (correction >= 0);
                  snd_brk = (char *) (MORECORE (correction));

                  /*
                     If can't allocate correction, try to at least find out current
                     brk.  It might be enough to proceed without failing.

                     Note that if second sbrk did NOT fail, we assume that space
                     is contiguous with first sbrk. This is a safe assumption unless
                     program is multithreaded but doesn't use locks and a foreign sbrk
                     occurred between our first and second calls.
                   */

                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      correction = 0;
                      snd_brk = (char *) (MORECORE (0));
                    }
                  else
                    {
                      /* Call the `morecore' hook if necessary.  */
                      void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
                      if (__builtin_expect (hook != NULL, 0))
                        (*hook)();
                    }
                }

              /* handle non-contiguous cases */
              else
                {
                  if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
                    /* MORECORE/mmap must correctly align */
                    assert (((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0);
                  else
                    {
                      front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                      if (front_misalign > 0)
                        {
                          /*
                             Skip over some bytes to arrive at an aligned position.
                             We don't need to specially mark these wasted front bytes.
                             They will never be accessed anyway because
                             prev_inuse of av->top (and any chunk created from its start)
                             is always true after initialization.
                           */

                          aligned_brk += MALLOC_ALIGNMENT - front_misalign;
                        }
                    }

                  /* Find out current end of memory */
                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      snd_brk = (char *) (MORECORE (0));
                    }
                }

              /* Adjust top based on results of second sbrk */
              if (snd_brk != (char *) (MORECORE_FAILURE))
                {
                  av->top = (mchunkptr) aligned_brk;
                  set_head (av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
                  av->system_mem += correction;

                  /*
                     If not the first time through, we either have a
                     gap due to foreign sbrk or a non-contiguous region.  Insert a
                     double fencepost at old_top to prevent consolidation with space
                     we don't own. These fenceposts are artificial chunks that are
                     marked as inuse and are in any case too small to use.  We need
                     two to make sizes and alignments work out.
                   */

                  if (old_size != 0)
                    {
                      /*
                         Shrink old_top to insert fenceposts, keeping size a
                         multiple of MALLOC_ALIGNMENT. We know there is at least
                         enough space in old_top to do this.
                       */
                      old_size = (old_size - 4 * SIZE_SZ) & ~MALLOC_ALIGN_MASK;
                      set_head (old_top, old_size | PREV_INUSE);

                      /*
                         Note that the following assignments completely overwrite
                         old_top when old_size was previously MINSIZE.  This is
                         intentional. We need the fencepost, even if old_top otherwise gets
                         lost.
                       */
		      set_head (chunk_at_offset (old_top, old_size),
				(2 * SIZE_SZ) | PREV_INUSE);
		      set_head (chunk_at_offset (old_top, old_size + 2 * SIZE_SZ),
				(2 * SIZE_SZ) | PREV_INUSE);

                      /* If possible, release the rest. */
                      if (old_size >= MINSIZE)
                        {
                          _int_free (av, old_top, 1);
                        }
                    }
                }
            }
        }
    } /* if (av !=  &main_arena) */

  if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state (av);

  /* finally, do the allocation */
  p = av->top;
  size = chunksize (p);

  /* check that one of the above allocation paths succeeded */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);
    }

  /* catch all failure paths */
  __set_errno (ENOMEM);
  return 0;
}


/*
   systrim is an inverse of sorts to sysmalloc.  It gives memory back
   to the system (via negative arguments to sbrk) if there is unused
   memory at the `high' end of the malloc pool. It is called
   automatically by free() when top space exceeds the trim
   threshold. It is also called by the public malloc_trim routine.  It
   returns 1 if it actually released any memory, else 0.
 */

static int
systrim (size_t pad, mstate av)
{
  long top_size;         /* Amount of top-most memory */
  long extra;            /* Amount to release */
  long released;         /* Amount actually released */
  char *current_brk;     /* address returned by pre-check sbrk call */
  char *new_brk;         /* address returned by post-check sbrk call */
  size_t pagesize;
  long top_area;

  pagesize = GLRO (dl_pagesize);
  top_size = chunksize (av->top);

  top_area = top_size - MINSIZE - 1;
  if (top_area <= pad)
    return 0;

  /* Release in pagesize units and round down to the nearest page.  */
  extra = ALIGN_DOWN(top_area - pad, pagesize);

  if (extra == 0)
    return 0;

  /*
     Only proceed if end of memory is where we last set it.
     This avoids problems if there were foreign sbrk calls.
   */
  current_brk = (char *) (MORECORE (0));
  if (current_brk == (char *) (av->top) + top_size)
    {
      /*
         Attempt to release memory. We ignore MORECORE return value,
         and instead call again to find out where new end of memory is.
         This avoids problems if first call releases less than we asked,
         of if failure somehow altered brk value. (We could still
         encounter problems if it altered brk in some very bad way,
         but the only thing we can do is adjust anyway, which will cause
         some downstream failure.)
       */

      MORECORE (-extra);
      /* Call the `morecore' hook if necessary.  */
      void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
      if (__builtin_expect (hook != NULL, 0))
        (*hook)();
      new_brk = (char *) (MORECORE (0));

      LIBC_PROBE (memory_sbrk_less, 2, new_brk, extra);

      if (new_brk != (char *) MORECORE_FAILURE)
        {
          released = (long) (current_brk - new_brk);

          if (released != 0)
            {
              /* Success. Adjust top. */
              av->system_mem -= released;
              set_head (av->top, (top_size - released) | PREV_INUSE);
              check_malloc_state (av);
              return 1;
            }
        }
    }
  return 0;
}

static void
internal_function
munmap_chunk (mchunkptr p)
{
  INTERNAL_SIZE_T size = chunksize (p);

  assert (chunk_is_mmapped (p));

  /* Do nothing if the chunk is a faked mmapped chunk in the dumped
     main arena.  We never free this memory.  */
  if (DUMPED_MAIN_ARENA_CHUNK (p))
    return;

  uintptr_t block = (uintptr_t) p - prev_size (p);
  size_t total_size = prev_size (p) + size;
  /* Unfortunately we have to do the compilers job by hand here.  Normally
     we would test BLOCK and TOTAL-SIZE separately for compliance with the
     page size.  But gcc does not recognize the optimization possibility
     (in the moment at least) so we combine the two values into one before
     the bit test.  */
  if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
    {
      malloc_printerr (check_action, "munmap_chunk(): invalid pointer",
                       chunk2mem (p), NULL);
      return;
    }

  atomic_decrement (&mp_.n_mmaps);
  atomic_add (&mp_.mmapped_mem, -total_size);

  /* If munmap failed the process virtual memory address space is in a
     bad shape.  Just leave the block hanging around, the process will
     terminate shortly anyway since not much can be done.  */
  __munmap ((char *) block, total_size);
}

#if HAVE_MREMAP

static mchunkptr
internal_function
mremap_chunk (mchunkptr p, size_t new_size)
{
  size_t pagesize = GLRO (dl_pagesize);
  INTERNAL_SIZE_T offset = prev_size (p);
  INTERNAL_SIZE_T size = chunksize (p);
  char *cp;

  assert (chunk_is_mmapped (p));
  assert (((size + offset) & (GLRO (dl_pagesize) - 1)) == 0);

  /* Note the extra SIZE_SZ overhead as in mmap_chunk(). */
  new_size = ALIGN_UP (new_size + offset + SIZE_SZ, pagesize);

  /* No need to remap if the number of pages does not change.  */
  if (size + offset == new_size)
    return p;

  cp = (char *) __mremap ((char *) p - offset, size + offset, new_size,
                          MREMAP_MAYMOVE);

  if (cp == MAP_FAILED)
    return 0;

  p = (mchunkptr) (cp + offset);

  assert (aligned_OK (chunk2mem (p)));

  assert (prev_size (p) == offset);
  set_head (p, (new_size - offset) | IS_MMAPPED);

  INTERNAL_SIZE_T new;
  new = atomic_exchange_and_add (&mp_.mmapped_mem, new_size - size - offset)
        + new_size - size - offset;
  atomic_max (&mp_.max_mmapped_mem, new);
  return p;
}
#endif /* HAVE_MREMAP */

/*------------------------ Public wrappers. --------------------------------*/

void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)

void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }

  if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* See if the dynamic brk/mmap threshold needs adjusting.
	 Dumped fake mmapped chunks do not affect the threshold.  */
      if (!mp_.no_dyn_threshold
          && chunksize_nomask (p) > mp_.mmap_threshold
          && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX
	  && !DUMPED_MAIN_ARENA_CHUNK (p))
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
      return;
    }

  ar_ptr = arena_for_chunk (p);
  _int_free (ar_ptr, p, 0);
}
libc_hidden_def (__libc_free)

void *
__libc_realloc (void *oldmem, size_t bytes)
{
  mstate ar_ptr;
  INTERNAL_SIZE_T nb;         /* padded request size */

  void *newp;             /* chunk to return */

  void *(*hook) (void *, size_t, const void *) =
    atomic_forced_read (__realloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(oldmem, bytes, RETURN_ADDRESS (0));

#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0 && oldmem != NULL)
    {
      __libc_free (oldmem); return 0;
    }
#endif

  /* realloc of null is supposed to be same as malloc */
  if (oldmem == 0)
    return __libc_malloc (bytes);

  /* chunk corresponding to oldmem */
  const mchunkptr oldp = mem2chunk (oldmem);
  /* its size */
  const INTERNAL_SIZE_T oldsize = chunksize (oldp);

  if (chunk_is_mmapped (oldp))
    ar_ptr = NULL;
  else
    ar_ptr = arena_for_chunk (oldp);

  /* Little security check which won't hurt performance: the allocator
     never wrapps around at the end of the address space.  Therefore
     we can exclude some size values which might appear here by
     accident or by "design" from some intruder.  We need to bypass
     this check for dumped fake mmap chunks from the old main arena
     because the new malloc may provide additional alignment.  */
  if ((__builtin_expect ((uintptr_t) oldp > (uintptr_t) -oldsize, 0)
       || __builtin_expect (misaligned_chunk (oldp), 0))
      && !DUMPED_MAIN_ARENA_CHUNK (oldp))
    {
      malloc_printerr (check_action, "realloc(): invalid pointer", oldmem,
		       ar_ptr);
      return NULL;
    }

  checked_request2size (bytes, nb);

  if (chunk_is_mmapped (oldp))
    {
      /* If this is a faked mmapped chunk from the dumped main arena,
	 always make a copy (and do not free the old chunk).  */
      if (DUMPED_MAIN_ARENA_CHUNK (oldp))
	{
	  /* Must alloc, copy, free. */
	  void *newmem = __libc_malloc (bytes);
	  if (newmem == 0)
	    return NULL;
	  /* Copy as many bytes as are available from the old chunk
	     and fit into the new size.  NB: The overhead for faked
	     mmapped chunks is only SIZE_SZ, not 2 * SIZE_SZ as for
	     regular mmapped chunks.  */
	  if (bytes > oldsize - SIZE_SZ)
	    bytes = oldsize - SIZE_SZ;
	  memcpy (newmem, oldmem, bytes);
	  return newmem;
	}

      void *newmem;

#if HAVE_MREMAP
      newp = mremap_chunk (oldp, nb);
      if (newp)
        return chunk2mem (newp);
#endif
      /* Note the extra SIZE_SZ overhead. */
      if (oldsize - SIZE_SZ >= nb)
        return oldmem;                         /* do nothing */

      /* Must alloc, copy, free. */
      newmem = __libc_malloc (bytes);
      if (newmem == 0)
        return 0;              /* propagate failure */

      memcpy (newmem, oldmem, oldsize - 2 * SIZE_SZ);
      munmap_chunk (oldp);
      return newmem;
    }

  __libc_lock_lock (ar_ptr->mutex);

  newp = _int_realloc (ar_ptr, oldp, oldsize, nb);

  __libc_lock_unlock (ar_ptr->mutex);
  assert (!newp || chunk_is_mmapped (mem2chunk (newp)) ||
          ar_ptr == arena_for_chunk (mem2chunk (newp)));

  if (newp == NULL)
    {
      /* Try harder to allocate memory in other arenas.  */
      LIBC_PROBE (memory_realloc_retry, 2, bytes, oldmem);
      newp = __libc_malloc (bytes);
      if (newp != NULL)
        {
          memcpy (newp, oldmem, oldsize - SIZE_SZ);
          _int_free (ar_ptr, oldp, 0);
        }
    }

  return newp;
}
libc_hidden_def (__libc_realloc)

void *
__libc_memalign (size_t alignment, size_t bytes)
{
  void *address = RETURN_ADDRESS (0);
  return _mid_memalign (alignment, bytes, address);
}

static void *
_mid_memalign (size_t alignment, size_t bytes, void *address)
{
  mstate ar_ptr;
  void *p;

  void *(*hook) (size_t, size_t, const void *) =
    atomic_forced_read (__memalign_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(alignment, bytes, address);

  /* If we need less alignment than we give anyway, just relay to malloc.  */
  if (alignment <= MALLOC_ALIGNMENT)
    return __libc_malloc (bytes);

  /* Otherwise, ensure that it is at least a minimum chunk size */
  if (alignment < MINSIZE)
    alignment = MINSIZE;

  /* If the alignment is greater than SIZE_MAX / 2 + 1 it cannot be a
     power of 2 and will cause overflow in the check below.  */
  if (alignment > SIZE_MAX / 2 + 1)
    {
      __set_errno (EINVAL);
      return 0;
    }

  /* Check for overflow.  */
  if (bytes > SIZE_MAX - alignment - MINSIZE)
    {
      __set_errno (ENOMEM);
      return 0;
    }


  /* Make sure alignment is power of 2.  */
  if (!powerof2 (alignment))
    {
      size_t a = MALLOC_ALIGNMENT * 2;
      while (a < alignment)
        a <<= 1;
      alignment = a;
    }

  arena_get (ar_ptr, bytes + alignment + MINSIZE);

  p = _int_memalign (ar_ptr, alignment, bytes);
  if (!p && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_memalign_retry, 2, bytes, alignment);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      p = _int_memalign (ar_ptr, alignment, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  assert (!p || chunk_is_mmapped (mem2chunk (p)) ||
          ar_ptr == arena_for_chunk (mem2chunk (p)));
  return p;
}
/* For ISO C11.  */
weak_alias (__libc_memalign, aligned_alloc)
libc_hidden_def (__libc_memalign)

void *
__libc_valloc (size_t bytes)
{
  if (__malloc_initialized < 0)
    ptmalloc_init ();

  void *address = RETURN_ADDRESS (0);
  size_t pagesize = GLRO (dl_pagesize);
  return _mid_memalign (pagesize, bytes, address);
}

void *
__libc_pvalloc (size_t bytes)
{
  if (__malloc_initialized < 0)
    ptmalloc_init ();

  void *address = RETURN_ADDRESS (0);
  size_t pagesize = GLRO (dl_pagesize);
  size_t rounded_bytes = ALIGN_UP (bytes, pagesize);

  /* Check for overflow.  */
  if (bytes > SIZE_MAX - 2 * pagesize - MINSIZE)
    {
      __set_errno (ENOMEM);
      return 0;
    }

  return _mid_memalign (pagesize, rounded_bytes, address);
}

void *
__libc_calloc (size_t n, size_t elem_size)
{
  mstate av;
  mchunkptr oldtop, p;
  INTERNAL_SIZE_T bytes, sz, csz, oldtopsize;
  void *mem;
  unsigned long clearsize;
  unsigned long nclears;
  INTERNAL_SIZE_T *d;

  /* size_t is unsigned so the behavior on overflow is defined.  */
  bytes = n * elem_size;
#define HALF_INTERNAL_SIZE_T \
  (((INTERNAL_SIZE_T) 1) << (8 * sizeof (INTERNAL_SIZE_T) / 2))
  if (__builtin_expect ((n | elem_size) >= HALF_INTERNAL_SIZE_T, 0))
    {
      if (elem_size != 0 && bytes / elem_size != n)
        {
          __set_errno (ENOMEM);
          return 0;
        }
    }

  void *(*hook) (size_t, const void *) =
    atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      sz = bytes;
      mem = (*hook)(sz, RETURN_ADDRESS (0));
      if (mem == 0)
        return 0;

      return memset (mem, 0, sz);
    }

  sz = bytes;

  arena_get (av, sz);
  if (av)
    {
      /* Check if we hand out the top chunk, in which case there may be no
	 need to clear. */
#if MORECORE_CLEARS
      oldtop = top (av);
      oldtopsize = chunksize (top (av));
# if MORECORE_CLEARS < 2
      /* Only newly allocated memory is guaranteed to be cleared.  */
      if (av == &main_arena &&
	  oldtopsize < mp_.sbrk_base + av->max_system_mem - (char *) oldtop)
	oldtopsize = (mp_.sbrk_base + av->max_system_mem - (char *) oldtop);
# endif
      if (av != &main_arena)
	{
	  heap_info *heap = heap_for_ptr (oldtop);
	  if (oldtopsize < (char *) heap + heap->mprotect_size - (char *) oldtop)
	    oldtopsize = (char *) heap + heap->mprotect_size - (char *) oldtop;
	}
#endif
    }
  else
    {
      /* No usable arenas.  */
      oldtop = 0;
      oldtopsize = 0;
    }
  mem = _int_malloc (av, sz);


  assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
          av == arena_for_chunk (mem2chunk (mem)));

  if (mem == 0 && av != NULL)
    {
      LIBC_PROBE (memory_calloc_retry, 1, sz);
      av = arena_get_retry (av, sz);
      mem = _int_malloc (av, sz);
    }

  if (av != NULL)
    __libc_lock_unlock (av->mutex);

  /* Allocation failed even after a retry.  */
  if (mem == 0)
    return 0;

  p = mem2chunk (mem);

  /* Two optional cases in which clearing not necessary */
  if (chunk_is_mmapped (p))
    {
      if (__builtin_expect (perturb_byte, 0))
        return memset (mem, 0, sz);

      return mem;
    }

  csz = chunksize (p);

#if MORECORE_CLEARS
  if (perturb_byte == 0 && (p == oldtop && csz > oldtopsize))
    {
      /* clear only the bytes from non-freshly-sbrked memory */
      csz = oldtopsize;
    }
#endif

  /* Unroll clear of <= 36 bytes (72 if 8byte sizes).  We know that
     contents have an odd number of INTERNAL_SIZE_T-sized words;
     minimally 3.  */
  d = (INTERNAL_SIZE_T *) mem;
  clearsize = csz - SIZE_SZ;
  nclears = clearsize / sizeof (INTERNAL_SIZE_T);
  assert (nclears >= 3);

  if (nclears > 9)
    return memset (d, 0, clearsize);

  else
    {
      *(d + 0) = 0;
      *(d + 1) = 0;
      *(d + 2) = 0;
      if (nclears > 4)
        {
          *(d + 3) = 0;
          *(d + 4) = 0;
          if (nclears > 6)
            {
              *(d + 5) = 0;
              *(d + 6) = 0;
              if (nclears > 8)
                {
                  *(d + 7) = 0;
                  *(d + 8) = 0;
                }
            }
        }
    }

  return mem;
}

/*
   ------------------------------ malloc ------------------------------
 */

static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

  const char *errstr = NULL;

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
     SIZE_SZ bytes의 추가적인 overhead를 얻고, 사용가능한 alignment 단위로 나타내기 위해서, 사용자가 요청한 bytes를 nb로 바꿔준다. 최소 MINSIZE보다 작은 요청의 경우, MINSIZE를 리턴해준다. 말이 좀 어렵지만 간단히 정리해보면, 64bit OS 기준으로 요청한 크기에 8(SIZE_SZ) bytes 만큼 더하고, alignment 단위(0x10의 배수)로 나타낸 값을 nb에 저장한다는 것이다. 예를 들어, 24bytes를 요청하였다면, 24+8=0x20이므로 0x10의 배수여서 0x20이 chunk size가 되지만, 25bytes를 요청했을 경우, 25+8=0x21에서 align과정을 거쳐 chunk size가 0x30이 된다. 또한, 0 bytes를 요청했을 경우, 0+8=8 에서 align 과정을 거치면 chunk size가 0x10이지만, MINSIZE 값인 0x20보다 작으므로 chunk size는 0x20이 되게 된다.
   */

  checked_request2size (bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  
     사용할 수 있는 arena가 존재하지 않는다면, sysmalloc() 호출하여 mmap()을 통해 chunk를 할당받는다. alloc_perturb는 memset을 통해 chunk를 초기화해주는 함수이다.
  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }

  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ())) // fastbin 범위검사
    {
      idx = fastbin_index (nb); // nb에 해당하는 fastbin의 idx 값을 저장
      mfastbinptr *fb = &fastbin (av, idx); // arena에서 fastbin의 해당 idx 주소를 저장 &((ar_ptr)->fastbinsY[idx])과 같음.
      mchunkptr pp = *fb; // 해당 size의 fastbin list의 시작 주소 저장.
      do
        {
          victim = pp; // victim에 앞쪽 chunk의 주소가 저장된다.
          if (victim == NULL) // victim이 NULL이면 해당 fastbin에 list가 없음. 즉  해당 size의 free된 chunk가 없다는 뜻임. break하여 smallbin으로 넘어감.
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))// *fb == victim인지 비교하고, victim->fd를 fb에 저장한다. 즉 가장 앞쪽 chunk를 list에서 제거하는 동작과 같다. 이 함수는 다음과 같이 정의되는데, #define atomic_compare_and_exchange_val_acq(mem, newval, oldval) __sync_val_compare_and_swap (mem, oldval, newval) 해당 함수의 동작은 먼저, *mem == oldval인지 확인하여 동일하다면 *mem = newval한다는 의미이다. 또한 위의 동작은 atomic으로 이뤄진다. 즉, 다른 프로세스/스레드가 *mem, oldval, newval 값을 변경시키지 못하는 것이 보장되는 상태에서 수행된다. pp에는 oldval, 즉 victim이 저장된다. 
             != victim);
      if (victim != 0) // chunk가 존재한다면
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0)) // 꺼내온 victim의 chunk size가 실제 그 bin에 맞는 크기인지 검사한다. *exploit 시 fastbin의 chunk size를 맞춰줘야하는 이유*
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb); // remalloc을 통해 할당된 chunk인지 확인한다.
          void *p = chunk2mem (victim); // victim 주소부터 64bit 기준 0x10을 더한 값을 p에 저장한다. chunk header 부분을 넘어 payload 부분의 주소를 전달하기 위함이다.
          alloc_perturb (p, bytes); // memset 수행
          return p; // 주소 값을 반환한다. (종료)
        }
    }

  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
     small request인 경우, bins를 확인한다. smallbins는 각 각 하나의 size를 유지하기 때문에, bins 내에서 검색할 필요가 없다. large request인 경우, 가장 알맞은 size를 찾기위해 unsorted bin의 chunks가 처리될 때까지 기다려야 하지만, small request의 경우 바로 확인할 수 있어 좀 더 빠르다.
   */

  if (in_smallbin_range (nb)) // large bin의 최소 size보다 작으면
    {
      idx = smallbin_index (nb); // 해당 size의 smallbin의 idx를 구한다.
      bin = bin_at (av, idx); // #define bin_at(m, i) (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2])) - offsetof (struct malloc_chunk, fd))으로 정의되어 있으며, 해당 idx의 bin의 주소를 저장하는데 이때, 이 bin을 fd, bk를 가진 chunk로서 사용하기 위해 - 0x10 한 값을 저장한다.

      if ((victim = last (bin)) != bin) // bin->bk == bin인지 확인. 같으면 해당 bin 내에 free된 chunk가 없는 경우이다.
        {
          if (victim == 0) /* initialization check, 0이면 초기화가 되지 않은 상태이므로 malloc_consolidate()를 호출하여 초기화를 시켜준다.*/ 
            malloc_consolidate (av);
          else
            {
              bck = victim->bk; // victim->bk->fd == victim 확인 *exploit 시 주의*
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb); // #define set_inuse_bit_at_offset(p, s) (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)으로 정의되어 있음. 즉 다음 chunk의 3bit의 flag 중 prev_inuse bit를 설정한다.
              // 가장 끝에 존재하는 마지막 chunk를 할당한다.(LIFO)
              bin->bk = bck; // bin->bk = victim->bk
              bck->fd = bin; // victim->bk->fd = bin을 통해 bin list에서 victim을 제거하고, 남은 bin list를 연결한다.

              if (av != &main_arena) // main arena가 아닌 경우, 
		set_non_main_arena (victim); // 해당 chunk size의 3bit의 flag 중 non_main_arena bit를 설정한다.
              check_malloced_chunk (av, victim, nb); // 정상적으로 할당되었는지 확인한다.
              void *p = chunk2mem (victim); // victim 주소부터 64bit 기준 0x10을 더한 값을 p에 저장한다. chunk header 부분을 넘어 payload 부분의 주소를 전달하기 위함이다.
              alloc_perturb (p, bytes); // memset 수행
              return p; // 주소 값을 반환한다. (종료)
            }
        }
    }

  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
     ====================================================================
     large request인 경우, 계속하기 전에 fastbins을 통합한다.
     사용가능한 공간이 있는지 확인하기도 전에, 모든 fastbins을 없애버리는 것이 과도하게 보일 수도 있지만, 해당 동작은 일반적으로 fastbins와 관련된 문제인 단편화를 피할 수 있게 한다. 또한, 실제로 프로그램들은 small이나 large request 중 한가지만 실행하는 경향이 있지, 복합적으로 사용하지 않기 때문에 대부분의 프로그램에서 병합과정(consolidation)이 호출되지 않는다. 즉, large request를 받은 경우 당분간 small request가 없을 것이라고 가정한다. 자주 호출되는 프로그램은 반면 단편화되는 경향을 갖는다.
   */

  else // large bin인 경우
    {
      idx = largebin_index (nb); // 요청된 size에 따라 적절한 bin에 접근하기 위해 idx를 구하여 저장한다.
      if (have_fastchunks (av)) // av->flags에 FASTCHUNKS_BIT가 세팅되지 않은 경우
        malloc_consolidate (av); // 모든 fastbins 병합 (fragmentation 해결)
    }

/* 앞선 코드들에서 포인터를 리턴하지 않고, 여기까지 도달하였다면 이는 다음 중 한가지이상을 의미한다.  
  1. fastbin range이지만, 사용가능한 fastbin chunk가 존재하지 않는 경우
  2. smallbin range이지만, 사용가능한 smallbin chunk가 존재하지 않는 경우(초기화 중 malloc_consolidate를 호출)
  3. size가 large bin range인 경우
*/

  /*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
    ===========================================================================
    최근 free되거나 remainder된 chunks를 처리한다. 정확하게 size가 맞는 경우에만 처리하거나, small request인 경우에 chunk가 가장 최근 size가 일치하지 않는 chunk로부터의 remainder chunk일 경우 처리한다.
    검사한 chunk는 bins에 집어넣는다. 이 단계가 유일하게 bins에 chunks를 집어넣는 단계이다.

    여기에 존재하는 외부 루프는 malloc이 끝날 때까지 병합을 해야한다는 것을 알지 못하기 때문에 필요하다. 따라서 계속해서 시도해야한다. 즉, 병합을 언제해야할 지 모르기 때문에 그냥 계속 시도하는 것이다. 이 동작은 한 번만 일어나며, small request를 처리하기 위해 메모리를 확장해야하는 경우에만 발생한다.
   */


  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)) // unsorted->bk == unsorted가 될때까지 이므로, unsorted bin이 모두 소모될 때까지 반복하는 것과 같다. unsorted bin list에서 가장 뒷부분이 victim이 된다.
        {
          bck = victim->bk;
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
				   > av->system_mem, 0)) // victim의 chunk size가 minimum과 maximum 사이에 존재하는지 확인한다.
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
          size = chunksize (victim); // 해당 chunk의 size를 저장한다.

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
             =============================================================
             small request 시, unsorted bin의 유일한 chunk라면 last remainder를 사용하도록 한다. 이것은 연속적인 small requests에 대해 지역성을 향상시키기 위함이다. 이것은 가장 적합한 유일한 예외이며, small chunk에 정확히 맞지 않는 경우 적용된다.
           */

          if (in_smallbin_range (nb) && // small chunk 범위이고,
              bck == unsorted_chunks (av) && // 유일한 unsorted chunk이고,
              victim == av->last_remainder && // last remainder이고,
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) // chunk size가 (요청된 size + 최소 size)보다 크다면,
            { // 해당 chunk는 두 chunk로 나뉘게 된다.
              /* split and reattach remainder */
              remainder_size = size - nb; // 나누고 남은 크기를 remainder_size에 저장한다.
              remainder = chunk_at_offset (victim, nb); // 나누기 위한 offset을 저장한다.
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder; // unsorted bin chunk가 현재 이 chunk만 유일했으므로, 기존 victim 대신 나누고 남은 chunk를 새로운 unsorted bin chunk로 등록한다.
              av->last_remainder = remainder; // 나누고 남은 chunk는 arena의 last remainder chunk가 된다.
              remainder->bk = remainder->fd = unsorted_chunks (av); // remainder chunk와 unsorted bin을 이어준다. 해당 chunk가 unsorted bin의 유일한 chunk이므로 fd와 bk 모두에 unsorted chunk 주소를 저장한다.
              if (!in_smallbin_range (remainder_size)) // 나뉘고 남은 chunk의 크기가 smallbin range가 아니라면, 즉 large bin size인 경우
                {
                  remainder->fd_nextsize = NULL; // fd_nextsize 초기화
                  remainder->bk_nextsize = NULL; // bk_nextsize 초기화
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0)); // 할당해주려고 하는 victim 녀석의 size의 flag bit들에 prev_inuse와 non_main_arena(현재 사용하고 있는 arena가 main_arena가 아닐경우) bit를 설정한다. 이전 chunk가 확실히 사용 중인지에 관해서는 정확히 확신하지는 못하겠다. 추후 확인할 것
              set_head (remainder, remainder_size | PREV_INUSE); // 이전 chunk는 이제 할당해줄 것이므로 prev_inuse bit를 설정한다.
              set_foot (remainder, remainder_size); // remainder chunk와 인접한 다음 chunk의 prev size에 remainder_size를 저장한다.

              check_malloced_chunk (av, victim, nb); // 정상적으로 할당되었는지 확인한다. remalloc 여부와 prev_inuse bit 확인
              void *p = chunk2mem (victim); // victim 주소부터 64bit 기준 0x10을 더한 값을 p에 저장한다. chunk header 부분을 넘어 payload 부분의 주소를 전달하기 위함이다.
              alloc_perturb (p, bytes); // memset 수행
              return p; // 주소 값을 반환한다. (종료)
            }

        /*
        victim이 small chunk가 아니거나, unsorted bin에 chunk가 복수 개일 경우 또는, victim이 last remainder chunk가 아닌 경우에 다음 코드가 수행된다.
        */
          /* remove from unsorted list 
          victim을 unsorted list에서 제거한다.
          */
          unsorted_chunks (av)->bk = bck; // unsorted_bin->bk = victim->bk
          bck->fd = unsorted_chunks (av); // victim->bk->fd = unsorted_bin

          /* Take now instead of binning if exact fit */

          if (size == nb) // victim의 size가 정확하게 니즈에 맞을 경우
            {
              set_inuse_bit_at_offset (victim, size); // victim을 할당해주기 위해서 인접한 다음 chunk의 size의 flag 중 prev_inuse bit를 설정한다.
              if (av != &main_arena) // 현재 사용하는 arena가 main_arena가 아닌경우
		set_non_main_arena (victim); // victim chunk에 non_main_arena bit를 설정한다.
              check_malloced_chunk (av, victim, nb); // 제대로 할당되었는지 확인한다. remalloc 여부와 prev_inuse bit 확인
              void *p = chunk2mem (victim); // victim 주소부터 64bit 기준 0x10을 더한 값을 p에 저장한다. chunk header 부분을 넘어 payload 부분의 주소를 전달하기 위함이다.
              alloc_perturb (p, bytes); // memset 수행
              return p; // 주소 값을 반환한다. (종료)
            }

          /* 
          place chunk in bin 
          victim의 size가 할당해주기에 적합하지 않은 경우, 해당 size에 맞는 small bin or large bin에 집어 넣는다.
          */
          if (in_smallbin_range (size)) // unsorted bin에서 가져온 chunk가 small bin range인 경우 수행한다.
            {
              victim_index = smallbin_index (size); // 해당 size에 대한 small bin index를 가져온다.
              bck = bin_at (av, victim_index); // small bins 중, 해당 idx의 bin의 주소를 찾은 뒤, chunk로서 관리하기 위해, 실제 해당 bin의 주소가 아닌, 헤더가 포함된 주소를 bck에 저장한다. 즉, 실제 주소보다 64bit OS기준 0x10만큼 이전의 주소를 저장한다.
              fwd = bck->fd; // 현재 bck는 해당 bin list를 관리하는 chunk가 되었으므로, bck->fd는 해당 bin list에서 가장 앞에 존재하는 chunk를 의미한다.
            }
          else // unsorted bin에서 가져온 chunk가 large bin range인 경우 수행한다.
            {
              victim_index = largebin_index (size); // size에 해당하는 large bin index를 가져온다.
              bck = bin_at (av, victim_index); // large bins 중, 해당 idx의 bin의 주소를 찾은 뒤, chunk로서 관리하기 위해, 실제 해당 bin의 주소가 아닌, 헤더가 포함된 주소를 bck에 저장한다. 즉, 실제 주소보다 64bit OS기준 0x10만큼 이전의 주소를 저장한다.
              fwd = bck->fd; // 현재 bck는 해당 bin list를 관리하는 chunk가 되었으므로, bck->fd는 해당 bin list에서 가장 앞에 존재하는 chunk를 의미한다.

              /* 
              maintain large bins in sorted order 
              large bin은 크기 별로 정렬된 순서를 계속해서 유지해야한다.
              */
              if (fwd != bck) // victim을 집어 넣으려고 하는 bin list에 기존 chunk가 존재하는 경우, large bin은 크기 별로 정렬된 순서를 유지해야 하기때문에, 다음과 같이 추가적인 작업이 필요하다.
                {
                  /*
                   Or with inuse bit to speed comparisons 
                   비교 속도를 향상시키기 위해서 prev_inuse bit를 설정한다고 하는데 왜 그러는지 잘 모르겠다.
                  */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk)); // 해당 chunk가 main_arena chunk인지 확인한다. 왜하는지 모르겠음.. 설마사카 large bin 추가는 main_arena에만 일어나는 것인가...
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk)) // 추가하려는 victim의 size가 해당 large bin에서 가장 작은 chunk보다 크기가 작을 때
                    {
                      // fd_nextsize, bk_nextsize list에 victim chunk를 추가한다.
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else // victim의 size보다 작은 size의 chunk가 이미 해당 large bin list에 존재하는 경우, 즉 fd_nextsize, bk_nextsize list 중간에 삽입해야 하거나(size가 다른 경우), 기존 nextsize list chunk와 fd, bk list를 만들어야 하는 경우(size가 같은 경우)이다.
                    {
                      assert (chunk_main_arena (fwd)); // fwd가 main_arena인지 확인한다. 아니면 그대로 종료.
                      while ((unsigned long) size < chunksize_nomask (fwd))
                        { // victim의 size가 fwd의 size보다 크거나 같을 때까지 반복한다.
                          fwd = fwd->fd_nextsize;
			  assert (chunk_main_arena (fwd)); // main_arena 여부 확인
                        }

                      if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd)) // size가 같은 경우
                        /* 
                         Always insert in the second position.  
                         항상 두 번째 위치에 삽입한다. 첫 번째 chunk는 nextsize list를 구성하기 때문.
                        */
                        fwd = fwd->fd;
                      else // size가 다른 경우, nextsize list를 만들어줘야 하는 경우
                        { // nextsize list를 구성한다.
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk; // large bin은 병렬구조로 되어있는게 아니라 직렬 구조로 되어있다.
                    }
                }
              else // 추가하려고 하는 large bin에 기존 존재하는 chunk가 아예 없는 경우(list에 존재하는 chunk가 없는 경우)
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index); // 해당 bin list에 추가하였기 때문에, bin들에 chunk가 남아있는지 한번에 확인할 수 있는 binmap에 추가된 정보를 업데이트한다.
          // bck와 fwd 사이에 삽입한다.
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS) // unsorted bin의 chunk들의 size를 싹다 뒤져보며 할당하기 적합한 chunk를 찾는 이 동작은, unsorted bin에 존재하는 모든 chunk를 소모하거나, MAX_ITERS 값(10000)만큼 반복한다.
            break;
        }


      /*
         If a large request, scan through the chunks of current bin in
         sorted order to find smallest that fits.  Use the skip list for this.
         만약 large request라면, 해당 요청을 처리할 수 있는 크기를 갖는 chunk들 중 가장 작은 size의 bin을 찾기위해 정렬된 현재 chunk를 스캔한다. 이를 위해서 skip list를 활용한다.
         이전 동작으로 unsorted bin에 있던 chunks를 smallbin과 large bin으로 모두 집어넣게 되었고, 이제 요청을 처리하기 위해, large bin에서 적합한 chunk를 할당하기 위해 찾아본다.
         [+] large bin은 동일한 size의 list 내에서 두 번째 위치에 chunk를 삽입하고 빼내기 때문에, 마치 FIFO(First In First Out) 방식으로 동작한다.
       */
      if (!in_smallbin_range (nb)) // large bin size 검사
        {
          bin = bin_at (av, idx); // 해당 bin 주소를 저장한다.

          /* 
          skip scan if empty or largest chunk is too small 
          chunk가 empty하거나 bin 내의 가장 큰 chunk가 너무 작다면 스캔을 스킵한다.
          */
          if ((victim = first (bin)) != bin // chunk가 empty하지 않은 경우, 
	      && (unsigned long) chunksize_nomask (victim) // victim은 empty하지 않았다면 가장 첫 번째 chunk이므로 가장 큰 chunk를 나타낸다.
	        >= (unsigned long) (nb)) // 가장 큰 chunk의 크기가 요청보다 크다면
            {
              victim = victim->bk_nextsize; // 해당 bin 내에서 가장 작은 chunk를 victim에 저장한다.
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb))) // victim이 요청을 처리할 수 있는 size가 될 때까지 반복한다.
                victim = victim->bk_nextsize; // 작은 chunk부터 큰 chunk 순으로 요청처리에 적합한 chunk를 탐색한다.

              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  
                 해당 size의 첫 번째 entry(fd_nextsize, bk_nextsize list를 구성한 chunk)를 제거하지 않는다. skip list가 다시 라우팅되지 않도록 하기 위함이다.   
              */
              if (victim != last (bin) // 해당 chunk가 해당 bin에서 마지막 chunk(가장 크기가 작은 chunk)가 아닌 경우,
		  && chunksize_nomask (victim)
		    == chunksize_nomask (victim->fd)) // 해당 size의 chunk가 존재할 경우,
                victim = victim->fd; // 다음 chunk를 사용한다.

              remainder_size = size - nb; // remainder size를 계산한다.
              unlink (av, victim, bck, fwd); // bin list에서 해당 chunk를 제거한다.

              /* Exhaust */
              if (remainder_size < MINSIZE) // 남은 크기가 chunk의 chunk의 최소 크기보다 작은 경우
                {
                  set_inuse_bit_at_offset (victim, size); // remainder chunk에 prev_inuse bit를 설정한다.
                  if (av != &main_arena) // main_arena가 아닌 경우
		    set_non_main_arena (victim); // non_main_arena bit를 설정한다.
                }
              /* Split */
              else // remainder chunk를 구성할 수 있을 정도의 size를 갖는 경우
                {
                  remainder = chunk_at_offset (victim, nb); // remainder chunk의 포인터를 저장한다.
                  /* 
                     We cannot assume the unsorted list is empty and therefore have to perform a complete insert here.  
                     unsorted list가 empty하다고 가정할 수 없으므로, 여기에서 완벽한 삽입을 수행한다.
                  */
                  bck = unsorted_chunks (av); // unsorted bin header chunk를 저장한다.
                  fwd = bck->fd; // 첫 번째 unsorted bin chunk를 저장한다.
	  if (__glibc_unlikely (fwd->bk != bck)) // unsorted bin 이중 연결리스트가 유효한지 확인한다.
                    {
                      errstr = "malloc(): corrupted unsorted chunks";
                      goto errout;
                    }
                  // remainder chunk를 unsorted bin list에 삽입한다. 앞 쪽(HEAD)에 삽입한다. (unsorted bin은 FIFO로 동작)
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size)) // remainder chunk가 large bin size라면
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0)); // victim의 size에 flag bit를 설정한다.
                  set_head (remainder, remainder_size | PREV_INUSE); // remainder chunk는 victim과 물리적으로 연속되기 때문에, remainder chunk 이전에 존재하는 victim에 대해서 prev_inuse bit를 설정한다.
                  set_foot (remainder, remainder_size); // remainder chunk는 free된 상태이기 때문에, remainder chunk 다음에(물리적으로) 존재하는 chunk의 prev_size를 설정한다.
                  /*#define set_head(p, s)       ((p)->mchunk_size = (s))
                  #define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))*/
                }
              check_malloced_chunk (av, victim, nb); // 정상적으로 할당되었는지 확인한다.
              void *p = chunk2mem (victim); // victim 주소부터 64bit 기준 0x10을 더한 값을 p에 저장한다. chunk header 부분을 넘어 payload 부분의 주소를 전달하기 위함이다.
              alloc_perturb (p, bytes); // memset 수행
              return p; // 주소 값을 반환한다. (종료)
            }
        }

      /*
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.
         다음으로 큰 bin을 시작으로 bins를 스캔하면서 chunk를 검색한다.
         본 검색과정은 철저하게 아주 적합한 방법이다. 최근에 가장 사용되지 않은 the smallest chunk가 선택된다. 

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
         bitmap을 사용하면 대부분의 blocks이 비어있는지 않은지 확인하지 않아도 된다.
         아직 어떤 chunk도 반환되지 않은 warm-up 단계(앞선 단계들)동안 모든 bins를 건너 뛰는 특별한 경우는 생각보다 빠르다. 
       */

      ++idx; // large bin list의 index 값을 증가시킨다.
      bin = bin_at (av, idx); // large bin list의 header chunk를 저장한다.
      block = idx2block (idx); // 해당 large bin list에서 index에 맞는 블록을 저장한다. (shift 연산 수행)
      map = av->binmap[block]; // binmap[(NBINS / BITSPERMAP)]한 int 형 배열에서 해당 블록을 저장한다. 해당 bin list에 free chunk가 존재한다면 0이 아닐 것이다.
      bit = idx2bit (idx); // binmap의 매핑에서 특정 비트를 추출한다. 해당 bin list에 free chunk가 존재한다면 0이 아닐 것이다.

      for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.
          해당 블록 내에서 세팅된 bits가 없을 경우 해당 블록의 나머지는 스킵한다. (즉, ++block 한다.)  
          */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins/ 모든 binmap을 검사했다면 top chunk로 할당받는다.*/
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0); // 해당 bin이 empty한지 검사한다. free chunk가 없다면 block을 증가시켜 다음 bin을 검사한다.

              bin = bin_at (av, (block << BINMAPSHIFT)); // 검색된 block에 맞는 index 위치의 bin list를 저장한다.
              bit = 1;
            }

          /* Advance to bin with set bit. There must be one.
            설정된 bit로 진행한다. 해당 bit는 반드시 1이어야 한다.  
          */
          while ((bit & map) == 0) // bit가 1이 아니면 empty한 상태이다.
            {
              bin = next_bin (bin); // 다음 bin list를 저장한다.
              bit <<= 1;
              assert (bit != 0);
            }

          /* Inspect the bin. It is likely to be non-empty
            bin이 non-empty일 것 같으니 검사한다. 
          */
          victim = last (bin); // victim은 현재 bin의 가장 뒤 쪽(TAIL) chunk를 가리킨다.

          /*  If a false alarm (empty bin), clear the bit.
            bin이 empty한 잘못된 알람인 경우 bit를 제거한다.
          */
          if (victim == bin) // 초기화시 bins는 자기자신을 가리키므로 같다면 empty한 상태이다.
            {
              av->binmap[block] = map &= ~bit; /* Write through / bit를 제거한다.*/
              bin = next_bin (bin); // 다음 bin list를 저장한다.
              bit <<= 1;
            }

          else // 검색한 bin list가 empty하지않은 상태
            {
              size = chunksize (victim); // 탐색한 chunk의 크기를 저장한다.

              /*  We know the first chunk in this bin is big enough to use.
                현재 bin의 첫 번째 chunk가 사용하기에 충분히 큰지 확인한다.
               ?현재 victim은 bin->bk로 해당 bin list에서 가장 작은 chunk(가장 TAIL)를 가리키는데 왜 first chunk라는 표현이 나오는지 잘 모르겠다.
              */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb; // remainder size를 계산한다.

              /* unlink */
              unlink (av, victim, bck, fwd); // unlink로 victim을 bin list에서 분리한다.

              /* Exhaust */
              if (remainder_size < MINSIZE) // remainder size가 최소 chunk size보다 작은 경우 그냥 victim 통째로 반환한다.
                {
                  set_inuse_bit_at_offset (victim, size); // 다음(물리적) chunk에 prev_inuse bit를 설정한다.
                  if (av != &main_arena)
		    set_non_main_arena (victim); // victim이 main_arena가 아닐 경우 non_main_arena bit를 설정한다.
                }

              /* Split */
              else // remainder size가 최소 chunk size보다 크거나 같은 경우, 두 개의 chunk로 나눈다.
                {
                  remainder = chunk_at_offset (victim, nb); // remainder chunk 주소를 저장한다.

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.
                     여기에 와서는 unsorted bin list가 empty하다고 가정할 수 없으므로 이중연결리스트에 대한 삽입을 수행한다.
                    */
                  bck = unsorted_chunks (av); // unsorted bin header chunk를 저장한다.
                  fwd = bck->fd;
	  if (__glibc_unlikely (fwd->bk != bck)) // unsorted bin의 이중 연결리스트 검사
                    {
                      errstr = "malloc(): corrupted unsorted chunks 2";
                      goto errout;
                    }
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb)) // 요청 크기가 smallbin 범위이면 remainder chunk를 last remainder chunk로 등록한다. 
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size)) // large bin 범위이면 nextsize 필드를 초기화한다.
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0)); // victim의 size에 flag bit를 설정한다.
                  set_head (remainder, remainder_size | PREV_INUSE); // remainder chunk는 victim과 물리적으로 연속되기 때문에, remainder chunk 이전에 존재하는 victim에 대해서 prev_inuse bit를 설정한다.
                  set_foot (remainder, remainder_size); // remainder chunk는 free된 상태이기 때문에, remainder chunk 다음에(물리적으로) 존재하는 chunk의 prev_size를 설정한다.
                  /*#define set_head(p, s)       ((p)->mchunk_size = (s))
​                  #define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))*/
                }
              check_malloced_chunk (av, victim, nb); // 정상적으로 할당되었는지 확인한다.
              void *p = chunk2mem (victim); // victim 주소부터 64bit 기준 0x10을 더한 값을 p에 저장한다. chunk header 부분을 넘어 payload 부분의 주소를 전달하기 위함이다.
              alloc_perturb (p, bytes); // memset 수행
              return p; // 주소 값을 반환한다. (종료)
            }
        }

    use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).
         (요청이) 꽤 크다면, 메모리 끝의 chunk(top chunk, av->top이 가리킴)를 분리한다. 이 방법은 가장 적합한 검색 규칙이다.
         실제로, top chunk(av->top)은 필요에 따라 (시스템 제한까지) 확장될 수 있기 때문에, 다른 이용가능한 chunk보다 훨씬 크다.

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
         초기화 후에는 항상 top chunk(av->top)이 존재해야 한다. (즉, top chunk의 size가 항상 MINSIZE보다 크거나 같아야한다.) 그렇지 않고, 현재 요청에 의해 소모된 top chunk의 size가 MINSIZE보다 작을 경우에는, 다시 top chunk를 채운다. (이 과정이 존재하는 주된 이유는 sysmalloc에 경계 확장(fencepost)를 넣기 위해 MINSIZE 공간이 필요할 수도 있기 때문이다.)
       */

      victim = av->top; // top chunk에서 할당한다.
      size = chunksize (victim);

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) // top chunk가 요청을 처리하고도 MINSIZE 이상을 유지할 수 있는 충분한 크기를 갖는 경우
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder; // remainder chunk가 새로운 top chunk가 된다.
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0)); // 할당하려는 victim의 size에 flag bit를 설정한다.
          set_head (remainder, remainder_size | PREV_INUSE); // top chunk의 prev_inuse bit를 설정한다.

          check_malloced_chunk (av, victim, nb); // 정상적으로 할당되었는지 확인한다.
          void *p = chunk2mem (victim); // victim 주소부터 64bit 기준 0x10을 더한 값을 p에 저장한다. chunk header 부분을 넘어 payload 부분의 주소를 전달하기 위함이다.
          alloc_perturb (p, bytes); // memset 수행
          return p; // 주소 값을 반환한다. (종료)
        }

      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.
         atomic ops를 사용하여 fast chunks를 free할 때, 모든 블록 크기에 대해 여기로 오게 된다.
        */
      else if (have_fastchunks (av)) // fastbin chunks가 존재하는 경우
        {
          malloc_consolidate (av); // fastbins 병합과정
          /* restore original bin index 
            원래 bin index를 회복한다.
          */
          if (in_smallbin_range (nb)) // 요청한 크기가 small bin인 경우
            idx = smallbin_index (nb); // small bin index를 저장한다.
          else // 요청한 크기가 large bin인 경우
            idx = largebin_index (nb); // large bin index를 저장한다.
        }

      /*
         Otherwise, relay to handle system-dependent cases
         그렇지 않다면, 시스템에 종속적인 경우를 처리하기 위해 교체한다.
       */
      else // top chunk가 요청을 처리할 수 없는 경우
        {
          void *p = sysmalloc (nb, av); // sysmalloc을 통해 시스템에 메모리를 요청한다.
          if (p != NULL)
            alloc_perturb (p, bytes); // memset 수행
          return p; // 주소 값을 반환한다. (종료)
        }
    }
}

/*
   ------------------------------ free ------------------------------
 */

static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.
     성능에 해를 입히지 않는 약간의 보안 검사를 진행한다. : 할당자는 절대 주소 공간 끝을 둘러 쌀 수 없다. (즉, size가 -size보다 클 수 없어, 아래로 주소가 overflow 날 수 없다는 뜻)
     따라서, 침입자의 의해 만들어지거나 우연히 만들어져서 나타날 수 있는 size 값을 제외할 수 있다.
     */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0)) // __builtin_expect (condition, 0)이라는 것은 condition이 0이길 기대한다는 뜻이다. 따라서 condition이 0이 될 가능성이 높은 경우를 나타낸다. 아무튼, free되는 chunk의 size의 값과 해당 값이 memory align에 맞춰 정렬되었는지 확인한다.
    {
      errstr = "free(): invalid pointer";
    errout:
      if (!have_lock && locked)
        __libc_lock_unlock (av->mutex); // arena에 걸려있던 lock을 푼다.
      malloc_printerr (check_action, errstr, chunk2mem (p), av); // 오류를 출력한다.
      return;
    }
  /* We know that each chunk is at least MINSIZE bytes in size or a multiple of MALLOC_ALIGNMENT.  
    각 chunk의 size는 적어도 MINSIZE 이상이거나 MALLOC_ALIGNMENT의 배수이다.
  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      errstr = "free(): invalid size";
      goto errout;
    }

  check_inuse_chunk(av, p); // p에 대해 next chunk의 prev_inuse bit를 확인하는 등의 작업들을 수행한다. 해당 chunk가 사용 중이어야 한다.

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
    fastbin의 맞는다면, 해당 chunk를 fastbin에 넣어서 malloc 시 빨리 찾아 사용될 수 있도록 한다.
  */
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
  TRIM_FASTBINS가 설정되어 있는 경우, top chunk와 맞닿아 있는 chunk는 fastbins에 넣으면 안된다.
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) { // fastbin에 넣는 경우

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0) // next chunk의 size가 최소 chunk size보다 작은지 확인한다.
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0)) // next chunk의 size가 system이 허용하는 크기보다 큰 지 확인한다.
      {
	/* We might not have a lock at this point and concurrent modifications of system_mem might have let to a false positive.  Redo the test after getting the lock.  
  이 시점에서 lock이 없을 수도 있고, system_mem의 동시 수정으로 1종 오류(실제로 부정인데 긍정함)를 낼 수도 있다. lock을 건 후 다시 테스트를 수행한다.
  */
	if (have_lock //
	    || ({ assert (locked == 0);
		  __libc_lock_lock (av->mutex); // lock 다시 설정
		  locked = 1;
		  chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ // p의 next chunk의 size와 최소 chunk size 비교
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem; // next chunk의 크기가 system이 허용하는 메모리 크기보다 큰지 확인한다.
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
	if (! have_lock) //
	  {
	    __libc_lock_unlock (av->mutex); // lock을 해제한다.
	    locked = 0;
	  }
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ); // memset으로 초기화해준다.

    set_fastchunks(av); // 해당 arena가 fastbin chunk를 포함한다는 것을 알게하기 위한 fastchunks_flag를 설정한다.
    unsigned int idx = fastbin_index(size); // 해당 size에 맞는 index를 저장한다.
    fb = &fastbin (av, idx); // fastbin list를 저장한다.

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  
    p를 fastbin list에 추가한다.*/
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
	/* Check that the top of the bin is not the record we are going to add (i.e., double free).  
    bin list의 최상단(HEAD)와 추가하려는 chunk가 같은지 확인한다.*/
	if (__builtin_expect (old == p, 0)) // ** double free 확인 **
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
	  }
	/* Check that size of fastbin chunk at the top is the same as	   size of the chunk that we are adding.  We can dereference OLD only if we have the lock, otherwise it might have already been deallocated.  See use of OLD_IDX below for the actual check.  
     fastbin list의 앞(HEAD) 쪽의 chunk의 size와 현재 추가하려는 chunk의 size가 동일한지 확인한다. lock이 걸린 상태에서만 OLD를 역 참조할 수 있으며, 그렇지 않은 경우 이미 할당이 취소되었을 수 있다. 실제 확인을 위해서 아래의 OLD_IDX의 사용을 참조.
     */
	if (have_lock && old != NULL) // lock이 걸려있고, old(기존 freed fastbin chunk)가 존재하는 경우
	  old_idx = fastbin_index(chunksize(old)); // 기존 chunk의 size에 대한 index를 저장한다.
	p->fd = old2 = old; // p를 이전 fastbin list와 연결한다.
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2); // 이 함수는 다음과 같이 정의되는데, #define atomic_compare_and_exchange_val_acq(mem, newval, oldval) __sync_val_compare_and_swap (mem, oldval, newval) 해당 함수의 동작은 먼저, *mem == oldval인지 확인하여 동일하다면 *mem = newval한다는 의미이다. 또한 위의 동작은 atomic으로 이뤄진다. 즉, 다른 프로세스/스레드가 *mem, oldval, newval 값을 변경시키지 못하는 것이 보장되는 상태에서 수행된다. 즉, *fb와 old2를 비교하여 같으면 *fb = p한 뒤, old2를 리턴한다. 정상적으로 수행되었으면 old2 == old2가 된다.

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0)) // lock이 걸려있고, old가 존재한다면 old_idx와 p의 index를 비교한다.
      {
	errstr = "invalid fastbin entry (free)";
	goto errout;
      }
  } // fastbin에 p를 저장한다.


  /*
    Consolidate other non-mmapped chunks as they arrive.
    도착한 다른 non-mmapped chunks를 병합한다.
  */
  else if (!chunk_is_mmapped(p)) { // fastbin이 아니며, mmap을 통해 할당된 chunk가 아닌 경우
    if (! have_lock) { // unlock인 경우
      __libc_lock_lock (av->mutex); // lock을 건다.
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size); // next chunk의 offset을 저장한다.

    /* Lightweight tests: check whether the block is already the top block.
      p가 top chunk인지 확인하는 간단한 테스트 */
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  
      next chunk가 arena의 범위를 넘어서는지 확인한다.*/
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto errout;
      }
    /* Or whether the block is actually not marked used.  
      블록이 실제 사용된다고 표시되었는지 여부를 확인한다. (next chunk의 prev_inuse bit가 설정되어 사용 중이라고 표시되어야 함)*/
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto errout;
      }

    nextsize = chunksize(nextchunk); // next chunk size 저장
    if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0) // next chunk의 size가 최소 chunk size보다 작거나 system이 허용하는 메모리 크기보다 큰지 확인한다.
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (normal)";
	goto errout;
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ); // memset을 통해 초기화한다.

    /* consolidate backward 
      뒤로(previous chunk)과 병합한다. */
    if (!prev_inuse(p)) { // prev chunk가 free된 chunk라면(fastbin이 아닌)
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd); // prev chunk를 bin list에서 제거한다.
    }

    if (nextchunk != av->top) { // next chunk가 top chunk가 아닌 경우
      /* get and clear inuse bit 
        inuse bit를 가져오고 제거한다.*/
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize); // next chunk에 대한 next chunk의 prev_inuse bit를 이용하여 next chunk의 inuse bit를 가져온다.

      /* consolidate forward 
        앞(next chunk)와 병합한다.*/
      if (!nextinuse) { // next chunk가 사용 중이 아닌 경우
	unlink(av, nextchunk, bck, fwd); // next chunk 해제
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0); // p에 대한 next chunk의 prev_inuse bit를 제거한다.

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
  chunks를 unsorted bin에 집어 넣는다. chunks는 malloc()에서 다시 사용될 기회를 얻을 때까지 regular bins(small, large)에 들어가지 않는다. */
      bck = unsorted_chunks(av); // unsorted bin의 header chunk를 저장한다.
      fwd = bck->fd; // unsorted bin의 첫 번째 chunk를 저장한다.
      if (__glibc_unlikely (fwd->bk != bck)) // header chunk->fd->bk == header chunk인지 확인한다.
	{
	  errstr = "free(): corrupted unsorted chunks";
	  goto errout;
	}
      p->fd = fwd; // unsorted bin list에 삽입할 준비
      p->bk = bck;
      if (!in_smallbin_range(size)) // large bin 범위인 경우
	{
	  p->fd_nextsize = NULL; // nextsize 초기화
	  p->bk_nextsize = NULL;
	}
      // unsorted bin의 맨 앞(HEAD)에 현재 chunk를 추가한다. (FIFO) 다만 malloc 시 remainder chunk를 unsorted bin에 삽입할 때에는 TAIL 쪽에 넣는다.
      bck->fd = p; 
      fwd->bk = p;

      set_head(p, size | PREV_INUSE); // prev chunk에 대해 현재 chunk에 prev_inuse bit를 설정한다.
      set_foot(p, size); // 현재 chunk가 free 되었으므로 next chunk의 prev_size에 현재 chunk의 size를 저장한다.

      check_free_chunk(av, p); // free 잘 되었나 확인한다. prev inuse bit, align 등 이것저것 확인함
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
      만약 chunk가 메모리의 가장 높은 값의 경계를 갖는다면(top chunk랑 인접해있다면), top chunk로 병합한다.
    */
    else { // next chunk가 top chunk인 경우
      size += nextsize;
      set_head(p, size | PREV_INUSE); // prev chunk에 대해 prev_inuse bit 설정
      av->top = p; // top chunk로 병합한다.
      check_chunk(av, p);
    }

    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.
      큰 공간을 해제하는 경우, 가능한 주변 chunks를 모두 병합한다. 그런 다음, 만약 사용하지 않은 최상위 메모리가 trim 임계 값을 초과한다면, top chunk를 줄이도록 malloc_trim을 호출한다.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
      max_fast가 0이 아니라면, top chunk 경계에 fastbins이 있는지 알 수 없기 때문에, fastbins을 병합하지 않으면 임계 값에 도달했는지 확실히 알 수가 없다.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) { // FASTBIN 임계 값보다 큰 경우
      if (have_fastchunks(av)) // fastbin이 존재하면
	malloc_consolidate(av); // fastbin 병합을 수행한다.

      if (av == &main_arena) { // 현재 arena가 main_arena인 경우
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >= // top chunk의 size가 trim 임계 값보다 큰 경우
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av); // systrim()을 호출하여 top chunk의 size를 줄인다.
#endif
      } else { // 현재 arena가 main_arena가 아닌 경우, thread arena
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  
     비록 top chunk가 크지 않더라도, 해당 heap이 사라질 수 있기 때문에 항상 heap_trim()을 수행한다.*/
	heap_info *heap = heap_for_ptr(top(av)); // thread arena의 시작 포인터를 저장한다.

	assert(heap->ar_ptr == av); // arena 확인
	heap_trim(heap, mp_.top_pad);
      }
    }

    if (! have_lock) { // lock이 걸려있지 않다면
      assert (locked);
      __libc_lock_unlock (av->mutex); // unlock한다.
    }
  } // fastbin size가 아니며, mmap으로 할당되지 않은 chunk(즉, sbrk로 할당받은 chunk) 관리
  
  /*
    If the chunk was allocated via mmap, release via munmap().
    chunk가 mmap()을 통해 할당되었다면, munmap()을 호출하여 해제한다.
  */
  else { // mmap()을 통해 할당한 경우
    munmap_chunk (p); // munmap을 이용하여 해제한다.
  }
}

/*
  ------------------------- malloc_consolidate -------------------------

  malloc_consolidate is a specialized version of free() that tears
  down chunks held in fastbins.  Free itself cannot be used for this
  purpose since, among other things, it might place chunks back onto
  fastbins.  So, instead, we need to use a minor variant of the same
  code.
  malloc_consolidate는 fastbins에 저장된 chunks들을 해체하는 특수한 free()이다.
  free()는 다른 것들 중에서, chunks를 도로 fastbins에 저장할 수 있기 때문에, free() 자체는 이 목적을 위해 사용될 수 없다. 그래서 대신에, 같은 코드를 약간 변형시켜 사용해야한다.

  Also, because this routine needs to be called the first time through
  malloc anyway, it turns out to be the perfect place to trigger
  initialization code.
  또한, 이 루틴은 malloc을 통해 처음 호출되야 하기때문에, 초기화 코드를 실행시키기에 가장 적합한 위치라고 할 수 있다.
*/

static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;
  mchunkptr       bck;
  mchunkptr       fwd;

  /*
    If max_fast is 0, we know that av hasn't
    yet been initialized, in which case do so below
    global_max_fast (fastbin에서 처리되는 메모리의 최대 크기) 값이 0이라면, av가 초기화되지 않았다는 뜻이므로, 아래의 과정(else문)을 수행한다.
  */
  if (get_max_fast () != 0) { // 초기화가 된 경우
    clear_fastchunks(av); // av의 FASTCHUNKS_BIT를 제거한다.

    unsorted_bin = unsorted_chunks(av); // unsorted bin header chunk를 저장한다.

    /*
      Remove each chunk from fast bin and consolidate it, placing it
      then in unsorted bin. Among other reasons for doing this,
      placing in unsorted bin avoids needing to calculate actual bins
      until malloc is sure that chunks aren't immediately going to be
      reused anyway.
      fastbin에서 각각의 chunk를 제거하고, 병합시킨 다음, unsorted bin에 집어넣는다.
      이 작업을 하는 다른 이유들 중, unsorted bin에 집어넣는 것은 malloc이 chunks가 즉시 재사용되지 않을 것이라고 확신할 때까지 실제 bin을 계산할 필요가 없다는 것이 있다.
    */

    maxfb = &fastbin (av, NFASTBINS - 1); // fastbin 최대 bin list 주소
    fb = &fastbin (av, 0); // fastbin 최소 bin list 주소
    do { // fb가 maxfb가 될 때까지 반복한다.
      p = atomic_exchange_acq (fb, NULL); // fb에 lock을 건다. 
      if (p != 0) { // lock이 제대로 걸린 경우 동작한다.
	do { // 해당 fastbinlist 내에 free된 chunk가 모두 소모될 때까지 반복한다.
	  check_inuse_chunk(av, p); // 제대로 chunk로서 기능을 하는지에 대한 검사와, 물리적으로 next chunk에 prev_inuse bit가 제대로 걸려있는지 확인한다. (fastbin에 대해서는 늘 next chunk의 prev_inuse bit가 설정된다.)
	  nextp = p->fd; // binlist 내의 next chunk를 저장한다.

	  /* Slightly streamlined version of consolidation code in free() 
      free()의 병합 코드가 약간 간소화된 버전이다.
    */
	  size = chunksize (p); // 현재 chunk의 size를 저장한다.
	  nextchunk = chunk_at_offset(p, size); // 물리적으로 next chunk 저장
	  nextsize = chunksize(nextchunk); // next chunk의 size를 저장한다.

	  if (!prev_inuse(p)) { // 이전 chunk에대해 prev_inuse bit가 설정되지 않았다면(prev chunk가 free된 상태라면, fastbin인 경우 항상 next chunk(물리적)의 prev_inuse bit가 설정된다.)
	    prevsize = prev_size (p);
	    size += prevsize;
	    p = chunk_at_offset(p, -((long) prevsize)); // p에 prev chunk의 offset을 저장한다.
	    unlink(av, p, bck, fwd); // p는 항상 이중 연결리스트로 된 binlist이므로 unlink를 이용하여 binlist에서 제거한다.
	  }

	  if (nextchunk != av->top) { // nextchunk가 top chunk가 아닐 경우
	    nextinuse = inuse_bit_at_offset(nextchunk, nextsize); // nextchunk에대해 next chunk(물리적)의 prev_inuse bit를 확인하여 nextchunk가 사용 중인지 확인한다.(fastbin이 아닌 free된 chunk인지 확인)

	    if (!nextinuse) { // nextchunk가 fastbin이 아닌 free된 chunk인 경우
	      size += nextsize;
	      unlink(av, nextchunk, bck, fwd); // binlist에서 제거한다.
	    } else // nextchunk가 fastbin이거나 free된 chunk가 아닐 경우
	      clear_inuse_bit_at_offset(nextchunk, 0); // 현재 fastbin chunk에 대한 prev_inuse bit를 제거한다.

      // ** unsorted bin의 앞 쪽에 새로운 chunk를 추가한다. **
	    first_unsorted = unsorted_bin->fd;
	    unsorted_bin->fd = p;
	    first_unsorted->bk = p;

	    if (!in_smallbin_range (size)) { // 해당 bin이 large bin size인 경우 nextsize를 초기화한다.
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	    }

	    set_head(p, size | PREV_INUSE); // 물리적으로 이전 chunk는 사용 중인 chunk이므로 prev_inuse bit를 설정한다. (p의 prev_inuse bit이 1인 경우였거나, 혹은 p 이전의 prev chunk가 free된 chunk였다면 bins의 속하는 chunk였다면 이미 해당 chunk의 prev chunk와 병합했을 것이기 때문)
	    p->bk = unsorted_bin;
	    p->fd = first_unsorted;
	    set_foot(p, size); // 병합한 p에대해 물리적으로 next chunk의 prev_size에 값을 저장한다.
	  }

	  else { // next chunk가 top chunk인 경우, top chunk와 병합된다.
	    size += nextsize;
	    set_head(p, size | PREV_INUSE); // top chunk의 prev_inuse bit를 설정한다.
	    av->top = p; // top chunk가 된다.
	  }

	} while ( (p = nextp) != 0); // 해당 fastbinlist 내에 free된 chunk가 모두 소모될 때까지 반복한다.

      }
    } while (fb++ != maxfb); // fb가 maxfb가 될 때까지 반복한다.
  }
  else { // av 초기화가 되지 않은 경우
    malloc_init_state(av); // av를 초기화시켜준다.
    check_malloc_state(av); // 해당 arena에 대해서 chunk들이 정상적으로 관계되어 있는지 확인한다.
  }
}

/*
  ------------------------------ realloc ------------------------------
*/

void*
_int_realloc(mstate av, mchunkptr oldp, INTERNAL_SIZE_T oldsize,
	     INTERNAL_SIZE_T nb)
{
  mchunkptr        newp;            /* chunk to return */
  INTERNAL_SIZE_T  newsize;         /* its size */
  void*          newmem;          /* corresponding user mem */

  mchunkptr        next;            /* next contiguous chunk after oldp */

  mchunkptr        remainder;       /* extra space at end of newp */
  unsigned long    remainder_size;  /* its size */

  mchunkptr        bck;             /* misc temp for linking */
  mchunkptr        fwd;             /* misc temp for linking */

  unsigned long    copysize;        /* bytes to copy */
  unsigned int     ncopies;         /* INTERNAL_SIZE_T words to copy */
  INTERNAL_SIZE_T* s;               /* copy source */
  INTERNAL_SIZE_T* d;               /* copy destination */

  const char *errstr = NULL;

  /* oldmem size */
  if (__builtin_expect (chunksize_nomask (oldp) <= 2 * SIZE_SZ, 0)
      || __builtin_expect (oldsize >= av->system_mem, 0))
    {
      errstr = "realloc(): invalid old size";
    errout:
      malloc_printerr (check_action, errstr, chunk2mem (oldp), av);
      return NULL;
    }

  check_inuse_chunk (av, oldp);

  /* All callers already filter out mmap'ed chunks.  */
  assert (!chunk_is_mmapped (oldp));

  next = chunk_at_offset (oldp, oldsize);
  INTERNAL_SIZE_T nextsize = chunksize (next);
  if (__builtin_expect (chunksize_nomask (next) <= 2 * SIZE_SZ, 0)
      || __builtin_expect (nextsize >= av->system_mem, 0))
    {
      errstr = "realloc(): invalid next size";
      goto errout;
    }

  if ((unsigned long) (oldsize) >= (unsigned long) (nb))
    {
      /* already big enough; split below */
      newp = oldp;
      newsize = oldsize;
    }

  else
    {
      /* Try to expand forward into top */
      if (next == av->top &&
          (unsigned long) (newsize = oldsize + nextsize) >=
          (unsigned long) (nb + MINSIZE))
        {
          set_head_size (oldp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
          av->top = chunk_at_offset (oldp, nb);
          set_head (av->top, (newsize - nb) | PREV_INUSE);
          check_inuse_chunk (av, oldp);
          return chunk2mem (oldp);
        }

      /* Try to expand forward into next chunk;  split off remainder below */
      else if (next != av->top &&
               !inuse (next) &&
               (unsigned long) (newsize = oldsize + nextsize) >=
               (unsigned long) (nb))
        {
          newp = oldp;
          unlink (av, next, bck, fwd);
        }

      /* allocate, copy, free */
      else
        {
          newmem = _int_malloc (av, nb - MALLOC_ALIGN_MASK);
          if (newmem == 0)
            return 0; /* propagate failure */

          newp = mem2chunk (newmem);
          newsize = chunksize (newp);

          /*
             Avoid copy if newp is next chunk after oldp.
           */
          if (newp == next)
            {
              newsize += oldsize;
              newp = oldp;
            }
          else
            {
              /*
                 Unroll copy of <= 36 bytes (72 if 8byte sizes)
                 We know that contents have an odd number of
                 INTERNAL_SIZE_T-sized words; minimally 3.
               */

              copysize = oldsize - SIZE_SZ;
              s = (INTERNAL_SIZE_T *) (chunk2mem (oldp));
              d = (INTERNAL_SIZE_T *) (newmem);
              ncopies = copysize / sizeof (INTERNAL_SIZE_T);
              assert (ncopies >= 3);

              if (ncopies > 9)
                memcpy (d, s, copysize);

              else
                {
                  *(d + 0) = *(s + 0);
                  *(d + 1) = *(s + 1);
                  *(d + 2) = *(s + 2);
                  if (ncopies > 4)
                    {
                      *(d + 3) = *(s + 3);
                      *(d + 4) = *(s + 4);
                      if (ncopies > 6)
                        {
                          *(d + 5) = *(s + 5);
                          *(d + 6) = *(s + 6);
                          if (ncopies > 8)
                            {
                              *(d + 7) = *(s + 7);
                              *(d + 8) = *(s + 8);
                            }
                        }
                    }
                }

              _int_free (av, oldp, 1);
              check_inuse_chunk (av, newp);
              return chunk2mem (newp);
            }
        }
    }

  /* If possible, free extra space in old or extended chunk */

  assert ((unsigned long) (newsize) >= (unsigned long) (nb));

  remainder_size = newsize - nb;

  if (remainder_size < MINSIZE)   /* not enough extra to split off */
    {
      set_head_size (newp, newsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_inuse_bit_at_offset (newp, newsize);
    }
  else   /* split remainder */
    {
      remainder = chunk_at_offset (newp, nb);
      set_head_size (newp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      /* Mark remainder as inuse so free() won't complain */
      set_inuse_bit_at_offset (remainder, remainder_size);
      _int_free (av, remainder, 1);
    }

  check_inuse_chunk (av, newp);
  return chunk2mem (newp);
}

/*
   ------------------------------ memalign ------------------------------
 */

static void *
_int_memalign (mstate av, size_t alignment, size_t bytes)
{
  INTERNAL_SIZE_T nb;             /* padded  request size */
  char *m;                        /* memory returned by malloc call */
  mchunkptr p;                    /* corresponding chunk */
  char *brk;                      /* alignment point within p */
  mchunkptr newp;                 /* chunk to return */
  INTERNAL_SIZE_T newsize;        /* its size */
  INTERNAL_SIZE_T leadsize;       /* leading space before alignment point */
  mchunkptr remainder;            /* spare room at end to split off */
  unsigned long remainder_size;   /* its size */
  INTERNAL_SIZE_T size;



  checked_request2size (bytes, nb);

  /*
     Strategy: find a spot within that chunk that meets the alignment
     request, and then possibly free the leading and trailing space.
   */


  /* Call malloc with worst case padding to hit alignment. */

  m = (char *) (_int_malloc (av, nb + alignment + MINSIZE));

  if (m == 0)
    return 0;           /* propagate failure */

  p = mem2chunk (m);

  if ((((unsigned long) (m)) % alignment) != 0)   /* misaligned */

    { /*
                Find an aligned spot inside chunk.  Since we need to give back
                leading space in a chunk of at least MINSIZE, if the first
                calculation places us at a spot with less than MINSIZE leader,
                we can move to the next aligned spot -- we've allocated enough
                total room so that this is always possible.
                 */
      brk = (char *) mem2chunk (((unsigned long) (m + alignment - 1)) &
                                - ((signed long) alignment));
      if ((unsigned long) (brk - (char *) (p)) < MINSIZE)
        brk += alignment;

      newp = (mchunkptr) brk;
      leadsize = brk - (char *) (p);
      newsize = chunksize (p) - leadsize;

      /* For mmapped chunks, just adjust offset */
      if (chunk_is_mmapped (p))
        {
          set_prev_size (newp, prev_size (p) + leadsize);
          set_head (newp, newsize | IS_MMAPPED);
          return chunk2mem (newp);
        }

      /* Otherwise, give back leader, use the rest */
      set_head (newp, newsize | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_inuse_bit_at_offset (newp, newsize);
      set_head_size (p, leadsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
      _int_free (av, p, 1);
      p = newp;

      assert (newsize >= nb &&
              (((unsigned long) (chunk2mem (p))) % alignment) == 0);
    }

  /* Also give back spare room at the end */
  if (!chunk_is_mmapped (p))
    {
      size = chunksize (p);
      if ((unsigned long) (size) > (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (p, nb);
          set_head (remainder, remainder_size | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head_size (p, nb);
          _int_free (av, remainder, 1);
        }
    }

  check_inuse_chunk (av, p);
  return chunk2mem (p);
}


/*
   ------------------------------ malloc_trim ------------------------------
 */

static int
mtrim (mstate av, size_t pad)
{
  /* Don't touch corrupt arenas.  */
  if (arena_is_corrupt (av))
    return 0;

  /* Ensure initialization/consolidation */
  malloc_consolidate (av);

  const size_t ps = GLRO (dl_pagesize);
  int psindex = bin_index (ps);
  const size_t psm1 = ps - 1;

  int result = 0;
  for (int i = 1; i < NBINS; ++i)
    if (i == 1 || i >= psindex)
      {
        mbinptr bin = bin_at (av, i);

        for (mchunkptr p = last (bin); p != bin; p = p->bk)
          {
            INTERNAL_SIZE_T size = chunksize (p);

            if (size > psm1 + sizeof (struct malloc_chunk))
              {
                /* See whether the chunk contains at least one unused page.  */
                char *paligned_mem = (char *) (((uintptr_t) p
                                                + sizeof (struct malloc_chunk)
                                                + psm1) & ~psm1);

                assert ((char *) chunk2mem (p) + 4 * SIZE_SZ <= paligned_mem);
                assert ((char *) p + size > paligned_mem);

                /* This is the size we could potentially free.  */
                size -= paligned_mem - (char *) p;

                if (size > psm1)
                  {
#if MALLOC_DEBUG
                    /* When debugging we simulate destroying the memory
                       content.  */
                    memset (paligned_mem, 0x89, size & ~psm1);
#endif
                    __madvise (paligned_mem, size & ~psm1, MADV_DONTNEED);

                    result = 1;
                  }
              }
          }
      }

#ifndef MORECORE_CANNOT_TRIM
  return result | (av == &main_arena ? systrim (pad, av) : 0);

#else
  return result;
#endif
}


int
__malloc_trim (size_t s)
{
  int result = 0;

  if (__malloc_initialized < 0)
    ptmalloc_init ();

  mstate ar_ptr = &main_arena;
  do
    {
      __libc_lock_lock (ar_ptr->mutex);
      result |= mtrim (ar_ptr, s);
      __libc_lock_unlock (ar_ptr->mutex);

      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  return result;
}


/*
   ------------------------- malloc_usable_size -------------------------
 */

static size_t
musable (void *mem)
{
  mchunkptr p;
  if (mem != 0)
    {
      p = mem2chunk (mem);

      if (__builtin_expect (using_malloc_checking == 1, 0))
        return malloc_check_get_size (p);

      if (chunk_is_mmapped (p))
	{
	  if (DUMPED_MAIN_ARENA_CHUNK (p))
	    return chunksize (p) - SIZE_SZ;
	  else
	    return chunksize (p) - 2 * SIZE_SZ;
	}
      else if (inuse (p))
        return chunksize (p) - SIZE_SZ;
    }
  return 0;
}


size_t
__malloc_usable_size (void *m)
{
  size_t result;

  result = musable (m);
  return result;
}

/*
   ------------------------------ mallinfo ------------------------------
   Accumulate malloc statistics for arena AV into M.
 */

static void
int_mallinfo (mstate av, struct mallinfo *m)
{
  size_t i;
  mbinptr b;
  mchunkptr p;
  INTERNAL_SIZE_T avail;
  INTERNAL_SIZE_T fastavail;
  int nblocks;
  int nfastblocks;

  /* Ensure initialization */
  if (av->top == 0)
    malloc_consolidate (av);

  check_malloc_state (av);

  /* Account for top */
  avail = chunksize (av->top);
  nblocks = 1;  /* top always exists */

  /* traverse fastbins */
  nfastblocks = 0;
  fastavail = 0;

  for (i = 0; i < NFASTBINS; ++i)
    {
      for (p = fastbin (av, i); p != 0; p = p->fd)
        {
          ++nfastblocks;
          fastavail += chunksize (p);
        }
    }

  avail += fastavail;

  /* traverse regular bins */
  for (i = 1; i < NBINS; ++i)
    {
      b = bin_at (av, i);
      for (p = last (b); p != b; p = p->bk)
        {
          ++nblocks;
          avail += chunksize (p);
        }
    }

  m->smblks += nfastblocks;
  m->ordblks += nblocks;
  m->fordblks += avail;
  m->uordblks += av->system_mem - avail;
  m->arena += av->system_mem;
  m->fsmblks += fastavail;
  if (av == &main_arena)
    {
      m->hblks = mp_.n_mmaps;
      m->hblkhd = mp_.mmapped_mem;
      m->usmblks = 0;
      m->keepcost = chunksize (av->top);
    }
}


struct mallinfo
__libc_mallinfo (void)
{
  struct mallinfo m;
  mstate ar_ptr;

  if (__malloc_initialized < 0)
    ptmalloc_init ();

  memset (&m, 0, sizeof (m));
  ar_ptr = &main_arena;
  do
    {
      __libc_lock_lock (ar_ptr->mutex);
      int_mallinfo (ar_ptr, &m);
      __libc_lock_unlock (ar_ptr->mutex);

      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  return m;
}

/*
   ------------------------------ malloc_stats ------------------------------
 */

void
__malloc_stats (void)
{
  int i;
  mstate ar_ptr;
  unsigned int in_use_b = mp_.mmapped_mem, system_b = in_use_b;

  if (__malloc_initialized < 0)
    ptmalloc_init ();
  _IO_flockfile (stderr);
  int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
  ((_IO_FILE *) stderr)->_flags2 |= _IO_FLAGS2_NOTCANCEL;
  for (i = 0, ar_ptr = &main_arena;; i++)
    {
      struct mallinfo mi;

      memset (&mi, 0, sizeof (mi));
      __libc_lock_lock (ar_ptr->mutex);
      int_mallinfo (ar_ptr, &mi);
      fprintf (stderr, "Arena %d:\n", i);
      fprintf (stderr, "system bytes     = %10u\n", (unsigned int) mi.arena);
      fprintf (stderr, "in use bytes     = %10u\n", (unsigned int) mi.uordblks);
#if MALLOC_DEBUG > 1
      if (i > 0)
        dump_heap (heap_for_ptr (top (ar_ptr)));
#endif
      system_b += mi.arena;
      in_use_b += mi.uordblks;
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = ar_ptr->next;
      if (ar_ptr == &main_arena)
        break;
    }
  fprintf (stderr, "Total (incl. mmap):\n");
  fprintf (stderr, "system bytes     = %10u\n", system_b);
  fprintf (stderr, "in use bytes     = %10u\n", in_use_b);
  fprintf (stderr, "max mmap regions = %10u\n", (unsigned int) mp_.max_n_mmaps);
  fprintf (stderr, "max mmap bytes   = %10lu\n",
           (unsigned long) mp_.max_mmapped_mem);
  ((_IO_FILE *) stderr)->_flags2 |= old_flags2;
  _IO_funlockfile (stderr);
}


/*
   ------------------------------ mallopt ------------------------------
 */
static inline int
__always_inline
do_set_trim_threshold (size_t value)
{
  LIBC_PROBE (memory_mallopt_trim_threshold, 3, value, mp_.trim_threshold,
	      mp_.no_dyn_threshold);
  mp_.trim_threshold = value;
  mp_.no_dyn_threshold = 1;
  return 1;
}

static inline int
__always_inline
do_set_top_pad (size_t value)
{
  LIBC_PROBE (memory_mallopt_top_pad, 3, value, mp_.top_pad,
	      mp_.no_dyn_threshold);
  mp_.top_pad = value;
  mp_.no_dyn_threshold = 1;
  return 1;
}

static inline int
__always_inline
do_set_mmap_threshold (size_t value)
{
  /* Forbid setting the threshold too high.  */
  if (value <= HEAP_MAX_SIZE / 2)
    {
      LIBC_PROBE (memory_mallopt_mmap_threshold, 3, value, mp_.mmap_threshold,
		  mp_.no_dyn_threshold);
      mp_.mmap_threshold = value;
      mp_.no_dyn_threshold = 1;
      return 1;
    }
  return 0;
}

static inline int
__always_inline
do_set_mmaps_max (int32_t value)
{
  LIBC_PROBE (memory_mallopt_mmap_max, 3, value, mp_.n_mmaps_max,
	      mp_.no_dyn_threshold);
  mp_.n_mmaps_max = value;
  mp_.no_dyn_threshold = 1;
  return 1;
}

static inline int
__always_inline
do_set_mallopt_check (int32_t value)
{
  LIBC_PROBE (memory_mallopt_check_action, 2, value, check_action);
  check_action = value;
  return 1;
}

static inline int
__always_inline
do_set_perturb_byte (int32_t value)
{
  LIBC_PROBE (memory_mallopt_perturb, 2, value, perturb_byte);
  perturb_byte = value;
  return 1;
}

static inline int
__always_inline
do_set_arena_test (size_t value)
{
  LIBC_PROBE (memory_mallopt_arena_test, 2, value, mp_.arena_test);
  mp_.arena_test = value;
  return 1;
}

static inline int
__always_inline
do_set_arena_max (size_t value)
{
  LIBC_PROBE (memory_mallopt_arena_max, 2, value, mp_.arena_max);
  mp_.arena_max = value;
  return 1;
}


int
__libc_mallopt (int param_number, int value)
{
  mstate av = &main_arena;
  int res = 1;

  if (__malloc_initialized < 0)
    ptmalloc_init ();
  __libc_lock_lock (av->mutex);
  /* Ensure initialization/consolidation */
  malloc_consolidate (av);

  LIBC_PROBE (memory_mallopt, 2, param_number, value);

  switch (param_number)
    {
    case M_MXFAST:
      if (value >= 0 && value <= MAX_FAST_SIZE)
        {
          LIBC_PROBE (memory_mallopt_mxfast, 2, value, get_max_fast ());
          set_max_fast (value);
        }
      else
        res = 0;
      break;

    case M_TRIM_THRESHOLD:
      do_set_trim_threshold (value);
      break;

    case M_TOP_PAD:
      do_set_top_pad (value);
      break;

    case M_MMAP_THRESHOLD:
      res = do_set_mmap_threshold (value);
      break;

    case M_MMAP_MAX:
      do_set_mmaps_max (value);
      break;

    case M_CHECK_ACTION:
      do_set_mallopt_check (value);
      break;

    case M_PERTURB:
      do_set_perturb_byte (value);
      break;

    case M_ARENA_TEST:
      if (value > 0)
	do_set_arena_test (value);
      break;

    case M_ARENA_MAX:
      if (value > 0)
	do_set_arena_test (value);
      break;
    }
  __libc_lock_unlock (av->mutex);
  return res;
}
libc_hidden_def (__libc_mallopt)


/*
   -------------------- Alternative MORECORE functions --------------------
 */


/*
   General Requirements for MORECORE.

   The MORECORE function must have the following properties:

   If MORECORE_CONTIGUOUS is false:

 * MORECORE must allocate in multiples of pagesize. It will
      only be called with arguments that are multiples of pagesize.

 * MORECORE(0) must return an address that is at least
      MALLOC_ALIGNMENT aligned. (Page-aligning always suffices.)

   else (i.e. If MORECORE_CONTIGUOUS is true):

 * Consecutive calls to MORECORE with positive arguments
      return increasing addresses, indicating that space has been
      contiguously extended.

 * MORECORE need not allocate in multiples of pagesize.
      Calls to MORECORE need not have args of multiples of pagesize.

 * MORECORE need not page-align.

   In either case:

 * MORECORE may allocate more memory than requested. (Or even less,
      but this will generally result in a malloc failure.)

 * MORECORE must not allocate memory when given argument zero, but
      instead return one past the end address of memory from previous
      nonzero call. This malloc does NOT call MORECORE(0)
      until at least one call with positive arguments is made, so
      the initial value returned is not important.

 * Even though consecutive calls to MORECORE need not return contiguous
      addresses, it must be OK for malloc'ed chunks to span multiple
      regions in those cases where they do happen to be contiguous.

 * MORECORE need not handle negative arguments -- it may instead
      just return MORECORE_FAILURE when given negative arguments.
      Negative arguments are always multiples of pagesize. MORECORE
      must not misinterpret negative args as large positive unsigned
      args. You can suppress all such calls from even occurring by defining
      MORECORE_CANNOT_TRIM,

   There is some variation across systems about the type of the
   argument to sbrk/MORECORE. If size_t is unsigned, then it cannot
   actually be size_t, because sbrk supports negative args, so it is
   normally the signed type of the same width as size_t (sometimes
   declared as "intptr_t", and sometimes "ptrdiff_t").  It doesn't much
   matter though. Internally, we use "long" as arguments, which should
   work across all reasonable possibilities.

   Additionally, if MORECORE ever returns failure for a positive
   request, then mmap is used as a noncontiguous system allocator. This
   is a useful backup strategy for systems with holes in address spaces
   -- in this case sbrk cannot contiguously expand the heap, but mmap
   may be able to map noncontiguous space.

   If you'd like mmap to ALWAYS be used, you can define MORECORE to be
   a function that always returns MORECORE_FAILURE.

   If you are using this malloc with something other than sbrk (or its
   emulation) to supply memory regions, you probably want to set
   MORECORE_CONTIGUOUS as false.  As an example, here is a custom
   allocator kindly contributed for pre-OSX macOS.  It uses virtually
   but not necessarily physically contiguous non-paged memory (locked
   in, present and won't get swapped out).  You can use it by
   uncommenting this section, adding some #includes, and setting up the
   appropriate defines above:

 *#define MORECORE osMoreCore
 *#define MORECORE_CONTIGUOUS 0

   There is also a shutdown routine that should somehow be called for
   cleanup upon program exit.

 *#define MAX_POOL_ENTRIES 100
 *#define MINIMUM_MORECORE_SIZE  (64 * 1024)
   static int next_os_pool;
   void *our_os_pools[MAX_POOL_ENTRIES];

   void *osMoreCore(int size)
   {
    void *ptr = 0;
    static void *sbrk_top = 0;

    if (size > 0)
    {
      if (size < MINIMUM_MORECORE_SIZE)
         size = MINIMUM_MORECORE_SIZE;
      if (CurrentExecutionLevel() == kTaskLevel)
         ptr = PoolAllocateResident(size + RM_PAGE_SIZE, 0);
      if (ptr == 0)
      {
        return (void *) MORECORE_FAILURE;
      }
      // save ptrs so they can be freed during cleanup
      our_os_pools[next_os_pool] = ptr;
      next_os_pool++;
      ptr = (void *) ((((unsigned long) ptr) + RM_PAGE_MASK) & ~RM_PAGE_MASK);
      sbrk_top = (char *) ptr + size;
      return ptr;
    }
    else if (size < 0)
    {
      // we don't currently support shrink behavior
      return (void *) MORECORE_FAILURE;
    }
    else
    {
      return sbrk_top;
    }
   }

   // cleanup any allocated memory pools
   // called as last thing before shutting down driver

   void osCleanupMem(void)
   {
    void **ptr;

    for (ptr = our_os_pools; ptr < &our_os_pools[MAX_POOL_ENTRIES]; ptr++)
      if (*ptr)
      {
         PoolDeallocate(*ptr);
 * ptr = 0;
      }
   }

 */


/* Helper code.  */

extern char **__libc_argv attribute_hidden;

static void
malloc_printerr (int action, const char *str, void *ptr, mstate ar_ptr)
{
  /* Avoid using this arena in future.  We do not attempt to synchronize this
     with anything else because we minimally want to ensure that __libc_message
     gets its resources safely without stumbling on the current corruption.  */
  if (ar_ptr)
    set_arena_corrupt (ar_ptr);

  if ((action & 5) == 5)
    __libc_message (action & 2, "%s\n", str);
  else if (action & 1)
    {
      char buf[2 * sizeof (uintptr_t) + 1];

      buf[sizeof (buf) - 1] = '\0';
      char *cp = _itoa_word ((uintptr_t) ptr, &buf[sizeof (buf) - 1], 16, 0);
      while (cp > buf)
        *--cp = '0';

      __libc_message (action & 2, "*** Error in `%s': %s: 0x%s ***\n",
                      __libc_argv[0] ? : "<unknown>", str, cp);
    }
  else if (action & 2)
    abort ();
}

/* We need a wrapper function for one of the additions of POSIX.  */
int
__posix_memalign (void **memptr, size_t alignment, size_t size)
{
  void *mem;

  /* Test whether the SIZE argument is valid.  It must be a power of
     two multiple of sizeof (void *).  */
  if (alignment % sizeof (void *) != 0
      || !powerof2 (alignment / sizeof (void *))
      || alignment == 0)
    return EINVAL;


  void *address = RETURN_ADDRESS (0);
  mem = _mid_memalign (alignment, size, address);

  if (mem != NULL)
    {
      *memptr = mem;
      return 0;
    }

  return ENOMEM;
}
weak_alias (__posix_memalign, posix_memalign)


int
__malloc_info (int options, FILE *fp)
{
  /* For now, at least.  */
  if (options != 0)
    return EINVAL;

  int n = 0;
  size_t total_nblocks = 0;
  size_t total_nfastblocks = 0;
  size_t total_avail = 0;
  size_t total_fastavail = 0;
  size_t total_system = 0;
  size_t total_max_system = 0;
  size_t total_aspace = 0;
  size_t total_aspace_mprotect = 0;



  if (__malloc_initialized < 0)
    ptmalloc_init ();

  fputs ("<malloc version=\"1\">\n", fp);

  /* Iterate over all arenas currently in use.  */
  mstate ar_ptr = &main_arena;
  do
    {
      fprintf (fp, "<heap nr=\"%d\">\n<sizes>\n", n++);

      size_t nblocks = 0;
      size_t nfastblocks = 0;
      size_t avail = 0;
      size_t fastavail = 0;
      struct
      {
	size_t from;
	size_t to;
	size_t total;
	size_t count;
      } sizes[NFASTBINS + NBINS - 1];
#define nsizes (sizeof (sizes) / sizeof (sizes[0]))

      __libc_lock_lock (ar_ptr->mutex);

      for (size_t i = 0; i < NFASTBINS; ++i)
	{
	  mchunkptr p = fastbin (ar_ptr, i);
	  if (p != NULL)
	    {
	      size_t nthissize = 0;
	      size_t thissize = chunksize (p);

	      while (p != NULL)
		{
		  ++nthissize;
		  p = p->fd;
		}

	      fastavail += nthissize * thissize;
	      nfastblocks += nthissize;
	      sizes[i].from = thissize - (MALLOC_ALIGNMENT - 1);
	      sizes[i].to = thissize;
	      sizes[i].count = nthissize;
	    }
	  else
	    sizes[i].from = sizes[i].to = sizes[i].count = 0;

	  sizes[i].total = sizes[i].count * sizes[i].to;
	}


      mbinptr bin;
      struct malloc_chunk *r;

      for (size_t i = 1; i < NBINS; ++i)
	{
	  bin = bin_at (ar_ptr, i);
	  r = bin->fd;
	  sizes[NFASTBINS - 1 + i].from = ~((size_t) 0);
	  sizes[NFASTBINS - 1 + i].to = sizes[NFASTBINS - 1 + i].total
					  = sizes[NFASTBINS - 1 + i].count = 0;

	  if (r != NULL)
	    while (r != bin)
	      {
		size_t r_size = chunksize_nomask (r);
		++sizes[NFASTBINS - 1 + i].count;
		sizes[NFASTBINS - 1 + i].total += r_size;
		sizes[NFASTBINS - 1 + i].from
		  = MIN (sizes[NFASTBINS - 1 + i].from, r_size);
		sizes[NFASTBINS - 1 + i].to = MAX (sizes[NFASTBINS - 1 + i].to,
						   r_size);

		r = r->fd;
	      }

	  if (sizes[NFASTBINS - 1 + i].count == 0)
	    sizes[NFASTBINS - 1 + i].from = 0;
	  nblocks += sizes[NFASTBINS - 1 + i].count;
	  avail += sizes[NFASTBINS - 1 + i].total;
	}

      __libc_lock_unlock (ar_ptr->mutex);

      total_nfastblocks += nfastblocks;
      total_fastavail += fastavail;

      total_nblocks += nblocks;
      total_avail += avail;

      for (size_t i = 0; i < nsizes; ++i)
	if (sizes[i].count != 0 && i != NFASTBINS)
	  fprintf (fp, "							      \
  <size from=\"%zu\" to=\"%zu\" total=\"%zu\" count=\"%zu\"/>\n",
		   sizes[i].from, sizes[i].to, sizes[i].total, sizes[i].count);

      if (sizes[NFASTBINS].count != 0)
	fprintf (fp, "\
  <unsorted from=\"%zu\" to=\"%zu\" total=\"%zu\" count=\"%zu\"/>\n",
		 sizes[NFASTBINS].from, sizes[NFASTBINS].to,
		 sizes[NFASTBINS].total, sizes[NFASTBINS].count);

      total_system += ar_ptr->system_mem;
      total_max_system += ar_ptr->max_system_mem;

      fprintf (fp,
	       "</sizes>\n<total type=\"fast\" count=\"%zu\" size=\"%zu\"/>\n"
	       "<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n"
	       "<system type=\"current\" size=\"%zu\"/>\n"
	       "<system type=\"max\" size=\"%zu\"/>\n",
	       nfastblocks, fastavail, nblocks, avail,
	       ar_ptr->system_mem, ar_ptr->max_system_mem);

      if (ar_ptr != &main_arena)
	{
	  heap_info *heap = heap_for_ptr (top (ar_ptr));
	  fprintf (fp,
		   "<aspace type=\"total\" size=\"%zu\"/>\n"
		   "<aspace type=\"mprotect\" size=\"%zu\"/>\n",
		   heap->size, heap->mprotect_size);
	  total_aspace += heap->size;
	  total_aspace_mprotect += heap->mprotect_size;
	}
      else
	{
	  fprintf (fp,
		   "<aspace type=\"total\" size=\"%zu\"/>\n"
		   "<aspace type=\"mprotect\" size=\"%zu\"/>\n",
		   ar_ptr->system_mem, ar_ptr->system_mem);
	  total_aspace += ar_ptr->system_mem;
	  total_aspace_mprotect += ar_ptr->system_mem;
	}

      fputs ("</heap>\n", fp);
      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  fprintf (fp,
	   "<total type=\"fast\" count=\"%zu\" size=\"%zu\"/>\n"
	   "<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n"
	   "<total type=\"mmap\" count=\"%d\" size=\"%zu\"/>\n"
	   "<system type=\"current\" size=\"%zu\"/>\n"
	   "<system type=\"max\" size=\"%zu\"/>\n"
	   "<aspace type=\"total\" size=\"%zu\"/>\n"
	   "<aspace type=\"mprotect\" size=\"%zu\"/>\n"
	   "</malloc>\n",
	   total_nfastblocks, total_fastavail, total_nblocks, total_avail,
	   mp_.n_mmaps, mp_.mmapped_mem,
	   total_system, total_max_system,
	   total_aspace, total_aspace_mprotect);

  return 0;
}
weak_alias (__malloc_info, malloc_info)


strong_alias (__libc_calloc, __calloc) weak_alias (__libc_calloc, calloc)
strong_alias (__libc_free, __cfree) weak_alias (__libc_free, cfree)
strong_alias (__libc_free, __free) strong_alias (__libc_free, free)
strong_alias (__libc_malloc, __malloc) strong_alias (__libc_malloc, malloc)
strong_alias (__libc_memalign, __memalign)
weak_alias (__libc_memalign, memalign)
strong_alias (__libc_realloc, __realloc) strong_alias (__libc_realloc, realloc)
strong_alias (__libc_valloc, __valloc) weak_alias (__libc_valloc, valloc)
strong_alias (__libc_pvalloc, __pvalloc) weak_alias (__libc_pvalloc, pvalloc)
strong_alias (__libc_mallinfo, __mallinfo)
weak_alias (__libc_mallinfo, mallinfo)
strong_alias (__libc_mallopt, __mallopt) weak_alias (__libc_mallopt, mallopt)

weak_alias (__malloc_stats, malloc_stats)
weak_alias (__malloc_usable_size, malloc_usable_size)
weak_alias (__malloc_trim, malloc_trim)


/* ------------------------------------------------------------
   History:

   [see ftp://g.oswego.edu/pub/misc/malloc.c for the history of dlmalloc]

 */
/*
 * Local variables:
 * c-basic-offset: 2
 * End:
 */
