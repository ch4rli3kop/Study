## 김말록씨 상세 분석일지 1 (glibc-2.25)



heap 공부는 malloc 동작 분석부터 하는게 맞는거 같다. malloc 관련해서 예전에 정리해놓은 걸 좀 더 다듬어 봤다. heap 공부를 하는 누군가에게(나를 포함한) 도움이 되기를 바란다.

glibc는 점점 update되어가며 사용자에게 다양한 기능을 제공하고 있다. 발견된 취약점, 매크로 상수들에 대한 패치와 같이 함수 동작에 대해 아주 크게 영향을 끼치지 않는 update가 있는 반면, 새로운 자료형 및 함수들을 추가하여 함수 동작에 큰 영향을 끼치는 update도 존재한다.

지금 분석할 malloc 함수 역시 glibc-2.26 version 이상부터 per-thread cache라는 개념이 등장하여 이전 glibc version의 malloc 동작과 비교해서 많은 차이를 갖는다. 

```html
NEWS for version 2.26
=====================

Major new features:

* A per-thread cache has been added to malloc. Access to the cache requires
  no locks and therefore significantly accelerates the fast path to allocate
  and free small amounts of memory. Refilling an empty cache requires
locking
  the underlying arena. Performance measurements show significant gains in a
  wide variety of user workloads. Workloads were captured using a special
  instrumented malloc and analyzed with a malloc simulator. Contributed by
  DJ Delorie with the help of Florian Weimer, and Carlos O'Donell.
```



원래 glibc-2.26의 malloc만 분석하려고 했는데 그냥 쓰는 김에 둘 다 서술해보도록 하겠다.



### __libc_malloc

malloc을 호출하면 내부적으로 이 __libc_malloc()이 호출된다. 

```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *) 
    = atomic_forced_read (__malloc_hook); // __malloc_hook에 등록된 주소를 저장한다.
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // hook 함수가 등록되어 있다면 hook 함수가 실행된다.

  arena_get (ar_ptr, bytes); // arena, 즉 mstate의 포인터를 저장한다.

  victim = _int_malloc (ar_ptr, bytes); // arena 포인터와 size를 인자로 _int_malloc()을 호출하여 메모리를 할당받는다. _int_malloc()이 malloc 동작의 핵심임
  
  /* Retry with another arena only if we were able to find a usable arena
     before.  
     사용가능한 다른 arena를 이용하여(찾을 수 있다면) 재할당을 시도한다.*/
  if (!victim && ar_ptr != NULL) // 첫 시도에서 못 받았다면
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL) 
    __libc_lock_unlock (ar_ptr->mutex); // 할당이 완료되었으므로 lock(mutex)을 해제한다.

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim))); // 정상적으로 할당이 되었는지 확인한다.
  return victim; // chunk를 반환한다. (malloc 종료)
}
libc_hidden_def (__libc_malloc)
```

요약하면 다음과 같다.

1. __malloc_hook 함수가 등록되어 있다면, 해당 함수를 호출한다.
2. arena의 header, 즉 malloc_state의 포인터를 가져오기 위해 arena_get()을 호출한다.
3. 가져온 arena 포인터와 size(bytes)를 이용하여 _int_malloc()을 호출한다.
4. chunk를 정상적으로 할당받지 못했다면, 다른 arena를 이용하여 재할당을 시도한다.
5. 할당이 완료되었으므로 arena의 lock(mutex)을 해제한다.
6. chunk를 반환하기 전, 다음 중 적어도 한가지 조건을 만족해야 한다.
   - 반환된 chunk의 포인터가 NULL임 (chunk 할당 실패?)
   - chunk가 mmap()을 이용해서 할당됨
   - 해당 chunk에 대한 arena가 ar_ptr에 저장된 arena와 동일해야 함
7. chunk를 반환한다. (malloc 종료)



### _int_malloc

_int_malloc() 함수는 다음과 같이 동작한다. arena와 bytes(=사용자가 요청한 malloc 크기)를 인자로 받는다. 

##### _int_malloc의 local 변수

```c
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
```

위와 같은 로컬 변수들을 사용한다.



##### size 변환

```c
  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */
  checked_request2size (bytes, nb);
```

SIZE_SZ bytes의 추가적인 overhead를 얻고, 사용가능한 alignment 단위로 나타내기 위해서, 사용자가 요청한 bytes를 nb로 바꿔준다. 최소 MINSIZE보다 작은 요청의 경우, MINSIZE를 리턴해준다. 말이 좀 어렵지만 간단히 정리해보면, 64bit OS 기준으로 요청한 크기에 8(SIZE_SZ) bytes 만큼 더하고, alignment 단위(0x10의 배수)로 나타낸 값을 nb에 저장한다는 것이다. 예를 들어, 24bytes를 요청하였다면, 24+8=0x20이므로 0x10의 배수여서 0x20이 chunk size가 되지만, 25bytes를 요청했을 경우, 25+8=0x21에서 align과정을 거쳐 chunk size가 0x30이 된다. 또한, 0 bytes를 요청했을 경우, 0+8=8 에서 align 과정을 거치면 chunk size가 0x10이지만, MINSIZE 값인 0x20보다 작으므로 chunk size는 0x20이 되게 된다.



##### 사용가능한 arena가 없을 경우

```c
  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av); // sysmalloc() 호출
      if (p != NULL)
	alloc_perturb (p, bytes); // memset 초기화
      return p; // 할당받은 chunk를 반환한다.
    }
```

사용할 수 있는 arena가 존재하지 않는다면, sysmalloc() 호출하여 mmap()을 통해 chunk를 할당받는다. alloc_perturb는 memset을 통해 chunk를 초기화해주는 함수이다.



##### fastbin range인 경우

```c
  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
     할당하려는 size가 fastbin에 적합하다면, 해당 size에 맞는 bin을 확인한다. 
     이 코드는 av가 초기화되지 않더라도 실행하는데에 안전하기 때문에, 검사없이 
     실행할 수 있어 시간을 절약할 수 있다.
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
             != victim); // 
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
```





##### smallbin range인 경우

```c
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
```



##### 사용되는 매크로 함수들

```c
#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))			      \
             - offsetof (struct malloc_chunk, fd))

/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))

# define check_malloced_chunk(A, P, N)   do_check_malloced_chunk (A, P, N)
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
```











##### consolidation(병합과정) fragment(단편화) 해결

```c
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
```



###### malloc_consolidate

```c

```







앞선 코드들에서 포인터를 리턴하지 않고, 여기까지 도달하였다면 이는 다음 중 한가지이상을 의미한다.

1. fastbin range이지만, 사용가능한 fastbin chunk가 존재하지 않는 경우

2. smallbin range이지만, 사용가능한 smallbin chunk가 존재하지 않는 경우(초기화 중 malloc_consolidate를 호출)

3. size가 large bin range인 경우





##### unsorted bin인 경우

```c
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

```







##### large bin인 경우

```c
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
```







```c
/* Set size/use field */
#define set_head(p, s)       ((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))
```





##### binmap을 이용하여 더 큰 bin list에서 검색

```c
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
```





##### binmap 매크로 함수들

```c
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
```





##### top chunk에서 할당

```c

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
```







##### malloc_consolidate()

```c
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
```

