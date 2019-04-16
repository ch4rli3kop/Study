## 김프리씨 상세 분석일지 2 (glibc-2.25)



heap 공부는 malloc 동작 분석부터 하는게 맞는거 같다. malloc 관련해서 예전에 정리해놓은 걸 좀 더 다듬어 봤다. heap 공부를 하는 누군가에게(나를 포함한) 도움이 되기를 바람

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



김말록씨에 대해 서술하고 나니 갑자기 의욕이 뚝 떨어졌지만, 시작한 김에 끝까지 다 가보자

이번에는 glibc-2.25의 free() 동작을 분석해보자.



역시 chunk의 구조라던가하는 기본적인 배경지식은 있다고 가정하고 진행한다. 



여러 자료들 참고 및 뇌피셜로 내가 열심히 주석을 달아놓은 malloc_glibc-2.25.c는 
<https://github.com/ch4rli3kop/Study/blob/master/malloc/malloc_glibc-2.25.c>에서 확인할 수 있다.

### __libc_free()

free()를 호출하면 내부적으로 이 __libc_free()가 호출된다.

```c
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0)) // __free_hook이 등록되어 있으면
    {
      (*hook)(mem, RETURN_ADDRESS (0)); // 해당 hook을 실행한다.
      return;
    }

  if (mem == 0)                              /* free(0) has no effect, free(0)은 동작하지 않음 */
    return;

  p = mem2chunk (mem); // mem는 chunk의 payload를 나타내므로 chunk header의 포인터를 가져온다.

  if (chunk_is_mmapped (p))                       /* release mmapped memory., mmap으로 할당된 chunk인 경우 */
    {
      /* See if the dynamic brk/mmap threshold needs adjusting.
	 Dumped fake mmapped chunks do not affect the threshold.  
   동적 brk/mmap 임계값을 조정할 필요가 있는지 확인한다. 덤프된 가짜 mmapped chunk는 임계 값에 영향을 끼치지 않는다.*/
      if (!mp_.no_dyn_threshold
          && chunksize_nomask (p) > mp_.mmap_threshold
          && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX
	  && !DUMPED_MAIN_ARENA_CHUNK (p))
        {
          mp_.mmap_threshold = chunksize (p); // mmap의 임계 값을 p의 size로 설정한다.
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p); // mmap으로 할당된 chunk를 해제한다.
      return;
    }

  ar_ptr = arena_for_chunk (p); // 해당 chunk의 arena 포인터를 저장하고 mutex에 lock을 건다.
  _int_free (ar_ptr, p, 0); // free 동작을 수행한다. 내부에서 arena mutex의 lock을 해제한다.
}
libc_hidden_def (__libc_free)
```

요약하면 다음과 같다.

1. __free_hook이 설정되어 있다면 해당 hook을 호출하고 종료한다.
2. 주어진 mem 포인터로부터 chunk의 포인터를 얻는다.
3. `mem`이 NULL이라면 반환한다. (종료)
4. 해당 chunk가 mmapped되면, 동적 brk/mmap 임계 값을 조정해야 하는 경우 `munmap_chunk`를 호출하여 메모리를 해제한다. (종료)
5. 그렇지 않은 경우, 해당 chunk의 arena 포인터를 가져오고, lock을 건다.
6. `_int_free`를 호출한다. 내부에서 mutex에 대한 lock을 해제한다.



다음은 free()의 핵심인 _int_free()이다. 주의깊게 살펴보도록 하자



### _int_free()

```c
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

```

##### 요약은 아니고 그냥 한국말

1. chunk의 헤더 정보를 통해 해당 chunk의 크기를 얻는다.

2. `p`가 `p + chunksize(p)` 이전에 존재하는지 확인한다.(in memory, 덮어쓰기를 피하기 위해서) 그렇지 않으면 error("free(): invalid pointer")를 발생시킨다.

3. chunk가 최소 `MINSIZE`의 크기인지 또는 `MALLOC_ALIGNMENT`의 배수인지 확인한다. 그렇지 않으면 error("free(): invalid pointer")를 발생시킨다.

   

4. chunk의 size가 fastbin 범위이면 다음 작업을 수행한다.

   1. next chunk의 size가 minimum과 maximum size(`av->system_mem`) 범위 안에 존재하는지 확인한다. 그렇지 않으면 error("free(): invalid next size (fast)")를 발생시킨다.

   2. 해당 chunk에 대해 `free_perturb`를 호출하여 초기화 작업을 수행한다.

   3. `av`에 `FASTCHUNKS_BIT`를 설정하여 해당 arena가 fastbin chunk를 포함한다고 표시한다.

   4. chunk size에 따라 fastbin array의 index를 가져온다.

   5. 해당 fastbin의 top에 존재하는 chunk와 우리가 추가하려는 chunk와 동일한지 확인한다. 동일하다면 중복해서 free를 호출한 경우이므로, error("double free or corruption (fasttop)")을 발생시킨다.

   6. 해당 fastbin list의 앞 쪽(HEAD)에 해당 chunk를 추가한다.

   7. old chunk(해당 fastbin list에 대해서 기존 HEAD에 위치했던 chunk)의 fastbin에서의 index와 방금 추가한 chunk의 index가 동일한지 확인한다. 동일하지 않다면 error("invalid fastbin entry (free)")를 발생시킨다. 

   8. 종료한다.

      

5. 해당 chunk가 mmapped 된 chunk가 아니라면 다음 작업을 수행한다. (fastbinsY가 아닌 bins인 경우)

   1. 해당 chunk가 top chunk인지 아닌지를 확인한다. top chunk라면, error("double free or corruption (top)")을 발생시킨다.

   2. next chunk(by memory)가 해당 arena의 범위 안에 존재하는지 확인한다. 그렇지 않다면 error("double free or corruption (out)")을 발생시킨다.

   3. next chunk(by memory)의 size에 prev_inuse bit가 설정되어있는지 아닌지 확인한다. 설정되어 있지 않다면, error("double free or corruption (!prev)")를 발생시킨다.

   4. next chunk의 size가 miminum과 maximum size (`av->system_mem`) 범위안에 존재하는지 확인한다. 그렇지 않다면, error("free(): invalid next size (normal)")을 발생시킨다.

   5. 해당 chunk에 대해서 `free_perturb`를 호출하여 초기화 작업을 수행한다.

   6. previous chunk (by memory)가 사용 중이 아니라면, previous chunk에 대해 `unlink`를 호출한다.

   7. next chunk (by memory)가 top chunk가 아니라면, 다음 작업을 수행한다.

      1. next chunk (by memory)가 사용 중이 아니라면, next chunk에 대해 `unlink`를 호출한다.
      2. (freed chunk 상태인) previous, next chunk (by memory)와 현재 chunk를 합병한 뒤, unsorted bin의 head에 추가한다. 추가 전, `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)`인지 확인한다. 그렇지 않다면, error("free(): corrupted unsorted chunks")를 발생시킨다.

   8. next chunks (by memory)가 top chunk라면, 해당 chunk를 하나의 top chunk로 병합시킨다.

   9. next chunk가 top chunk가 아니고 사용 중인 chunk라면, next chunk의 prev_inuse bit를 지운다.

      

6. 현재 chunk가 top chunk가 아니라면, unsorted bin에 추가하고 현재 chunk의 size 필드와 next chunk의 prev_size 필드에 현재 chunk의 size를 기록한다.

7. (병합된거 모두 포함) 현재 chunk의 size가 FASTBIN_CONSOLIDATION_THRESHOLD(65536)이상이고 현재 arena가 fast bin을 포함하면 malloc_consolidate를 호출하여 fast bin 병합을 수행한다.

8. 현재 chunk의 size가 정해진 trim_threshold(128K)이상이면 systrim() 함수를 호출하여 top chunk의 size를 줄인다. (systrim 함수는 top chunk가 sbrk를 통해 확장된 heap 영역에 속할 경우에만 수행되며 현재 top chunk의 크기에서 chunk 정보를 저장하기 위한 최소 크기와 top chunk가 기본적으로 가져야 할 여유 공간의 크기만큼을 뺀 크기를 페이지 단위로 조정하여 sbrk를 호출한다. 또한 __after_morecore_hook이 정의되어 있다면 해당 hook을 호출한 뒤 top chunk의 크기를 조정한다.)

9. 해당 chunk가 mmapped라면 `munmap_chunk`를 호출한다.





###### Reference

https://heap-exploitation.dhavalkapil.com/
https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf
https://tribal1012.tistory.com/141
http://studyfoss.egloos.com/5206979
https://say2.tistory.com/entry/glibc-mallocc%EC%9D%98-malloc%ED%95%A8%EC%88%98-%EB%B6%84%EC%84%9D-%EC%95%BD%EA%B0%84%EC%9D%98-exploit%EA%B4%80%EC%A0%90?category=669964





systrim()은 나중에 추가하겟음

