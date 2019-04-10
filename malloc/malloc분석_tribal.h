static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* 환형 이중 연결리스트 헤더 생성 */
  for (i = 1; i < NBINS; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
      // 비어있으므로 자기 자신을 가리키도록
    }

#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
  set_noncontiguous (av);     // flag에 NONCONTIGUOUS 설정
  if (av == &main_arena)
    set_max_fast (DEFAULT_MXFAST);  // 64 or 128로 정렬
  av->flags |= FASTCHUNKS_BIT;  //flagdp FASTCHUNKS_BIT 설정

  av->top = initial_top (av); // top chunk 결정
}

/*
   ------------------------------ malloc --------------------------------------------------------------------------------------------------------------------
 */

void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_lookup (ar_ptr);
  // 2개를 합쳐지는 것으로 패치됨 arena_get(ar_ptr, bytes);
  arena_lock (ar_ptr, bytes);   // mutex 설정
  if (!ar_ptr)
    return 0;

  victim = _int_malloc (ar_ptr, bytes);   // 이게 핵심
  if (!victim)    //victim이 NULL 인 경우, 오류 발생
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      if (__builtin_expect (ar_ptr != NULL, 1))
        {
          victim = _int_malloc (ar_ptr, bytes);
          (void) mutex_unlock (&ar_ptr->mutex);   // mutex 해제
        }
    }
  else
    (void) mutex_unlock (&ar_ptr->mutex);         // mutext 해제
  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  // 제대로 할당된건지 확인
  return victim;
}
libc_hidden_def (__libc_malloc)

void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* mem에 해당하는 chunk */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }

  if (mem == 0)                              /* free(0)는 효과 없음 */
    return;

  p = mem2chunk (mem);  // 메모리 포인터로부터 chunk 포인터 획득

  if (chunk_is_mmapped (p))                       /* mmap으로 할당된 메모리 해제 */
    {
      /* 동적 brk/mmap 임계값을 조정할 필요가 있는지 확인 */
      if (!mp_.no_dyn_threshold
          && p->size > mp_.mmap_threshold
          && p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          // mmap 임계값을 chunk의 크기로 설정
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p); //mmap으로 할당된 메모리 해제
      return;
    }

  ar_ptr = arena_for_chunk (p); // chunk가 속한 Arena 포인터 획득 및 lock
  _int_free (ar_ptr, p, 0);   // free의 주요 행위 시작
}
libc_hidden_def (__libc_free)

/*
   av는 arena ptr(Main or Thread), bytes는 사용자가 요청한 크기
 */
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* 요청되어 할당된 크기 저장 */
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

  printf("Inside malloc\n");

  checked_request2size (bytes, nb);
  //nb에는 요청한 크기를 메모리에 맞춰(16 or 32) 정렬하여 저장, 요청 크기가 chunk보다 작으면 chunk의 최소 크기만큼

  /*
     할당된 크기가 fastbin에 적합한지 확인, fastbin내의 free chunk가 있다면 이거 씀
     av가 초기화되지 않았어도 실행하므로 안전하고, 검사없이 수행하기에 시간 절약
   */
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb); // nb에서 8 or 16으로 나눈 후, 2를 뺀 값
      mfastbinptr *fb = &fastbin (av, idx); // 아레나의 fastbin idx의 주소를 fb에 저장
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)   // NULL이면 smallbin으로 넘어감.
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim)) // fb가 victim인 경우, victim->fd를 저장함(반환 값은 victim)
             != victim);  //fastbin 탐색(단일 연결리스트)
      if (victim != 0)
        {                       // fast bin 내의 free chunk를 가져옴
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))    // 꺼내온 victim의 chunk size가 실제 그 bin에 맞는 크기인지 검사한다. *exploit 시 fastbin의 chunk size를 맞춰줘야하는 이유*
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim));
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);    //victim이 NULL이 아닌 경우 재할당된 chunk인지 체크
          void *p = chunk2mem (victim); //victiom의 주소 정렬
          alloc_perturb (p, bytes);     //p의 주소에서 bytes만큼 memset
          return p;                     // 주소 값 반환
        }
    }

  /*
     요청이 small인 경우, 일반적인 bin인지 체크 "small bin"은 각각이 다른 size를 가짐, 검색해서 free chunk 존재하면 그거 꺼내서 사용
     bin 내부에 존재하는지 검색할 필요 없음
     (요청이 large인 경우, unsorted chunk 중 적합한 것이 있는지 대기
      small인 경우는 어디든 적합하므로 과정이 줄어 빠름)
   */

  if (in_smallbin_range (nb))     // largebin의 최소 사이즈보다 작은 경우
    {
      idx = smallbin_index (nb);  // 할당된 크기에 16 or 8을 나눈 후, 더하기 1, binlist가 8바이트 단위로 나뉘는걸 기억
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)   // bin->bk가 bin이 아닌 경우
        {   //특정 binlist의 시작 bk는 환형 이중연결리스트로 인해 가장 오래된 chunk가 됨
          if (victim == 0) /* 초기화 확인(아직 초기화가 안 된 상태) */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
              if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              // 다음 chunk의 size에 prev_inuse를 설정해 사용 중 표시
              bin->bk = bck; // bin list에서 이 chunk를 제거함.
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;     // main arena가 아닌 경우, size에 표시
              check_malloced_chunk (av, victim, nb);  //제대로 할당되었는지 체크
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }

  /*
     큰 요청인 경우, 계속하기 전에 fast bin을 통합한다.
     모든 fast bin을 날리는 것처럼 보일 수도 있지만 fast bin의 단편화 문제를
     해결한다.
     또한, 프로그램 내부에서 크고 작은 요청을 하긴 하지만 혼합하는 경우는 적음
     그래서 대부분의 프로그램에서 종합 통합을 호출하진 않음. 그리고 자주 호출되는
     프로그램은 단편화 문제가 발생
   */

  else    //large bin인 경우
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))     // flags에 fastchunk bit가 세팅 되지 않았을 때
        malloc_consolidate (av);    // 모든 fast bin 병합 실시(단편화 해결)
    }

  /*
     최근에 free되었거나 남아있는 chunk를 처리하고, 정확히 일치하는 경우에만 처리하거나,
     작은 요청인 경우, 가장 처음의 일치하지 않은 부분으로부터 chunk를 남김.
     지나온 다른 chunk들은 bin에 배치.
     이 단계는 chunk가 bin에 배치되는 모든 루틴 중에서 유일한 루틴임
     외부 루프는 malloc이 끝날 때 까지 통합하는 것을 알지 못하기 때문에 다시 시도할
     필요가 있어서 필요하다. 작은 요청을 처리해 메모리를 확장이 필요한 경우에만 한 번 발생
   */

  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {   //unsorted bin는 FIFO 방식의 환형 이중 연결리스트
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim));
          size = chunksize (victim);

          /*
             만일 small 요청시, unsorted bin의 유일한 chunk라면, last remainder를 사용하도록 함.  이 경우, 연속적인 small 요청이 동작하는 지역에 효과적임 이는 최적적합 상황에서만의 예외이고, 작은 chunk에 정확하게 맞지 않는 경우만 적용
           */

          if (in_smallbin_range (nb) && // small chunk 이고,
              bck == unsorted_chunks (av) && // unsorted chunk가 1개뿐,
              victim == av->last_remainder && // 게다가 last_remainder임
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            //size가 할당된 사이즈 + 최소 사이즈(남은 경우도 정렬되야 하므로)보다 큰 경우
            {
              /* 나머지를 분리하거나 재결합 */
              remainder_size = size - nb;   // 쪼개기 위해 남은 크기
              remainder = chunk_at_offset (victim, nb); // 남은 부분
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              // unsorted chunk에 나머지 부분만을 남김
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              // unsorted bin에 속하므로 환형 이중연결리스트 연결
              if (!in_smallbin_range (remainder_size))
                //남은 크기가 아직도 엄청 크다면
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              // 새로 할당된 녀석에 size의 Prev_inuse와 Non_Main_Arena 셋트
              set_head (remainder, remainder_size | PREV_INUSE);
              // 나머지도 셋트
              set_foot (remainder, remainder_size);
              // 나머지의 다음 chunk의 이전 크기 재설정
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);   // 재할당 완료
              return p;
            }

          /* size가 안 맞는 녀석은 unsorted list에서 제거(FIFO) */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* 사이즈가 정확한지 확인 */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes); // 정확하므로 재할당 완료
              return p;
            }

          /* size가 재할당에 적당하지 않았음 */

          if (in_smallbin_range (size))   //small bin인지 확인
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);  //victim이 들어갈 bin list
              fwd = bck->fd;    // 첫 번째 녀석 선정
            }
          else
            {   //large bin임
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* 정렬된 상태로 large bin 유지 */
              if (fwd != bck) //안에 내용물이 있었음
                {
                  /* Prev_Inuse를 사용하여 비교 속도 향상 */
                  size |= PREV_INUSE;
                  /* 최소 크기보다 작다면 아래의 루프를 우회 */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    { //맨 뒤의 녀석이 자신보다 크기가 클 때(자신이 가장 작음)
                      fwd = bck;    // 헤더의 뒤로 이동
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; //헤더의 뒤로 잘 끼워짐
                    }
                  else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size)
                        { //자신이 앞의 녀석보다 클 때까지
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }

                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* 항상 2번째 위치에 삽입  */
                        fwd = fwd->fd;
                        //앞의 녀석과 자신이 크기가 동일, 하지만 더 늦음
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                          //크기 정렬에 맞게 잘 들어감(맨 뒤가 가장 작음)
                        }
                      bck = fwd->bk;
                    }
                }
              else  //텅 비어있어서 자기자신을 가리키던 중
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          //bin에 뭔가 들어갔으므로 매핑 정보를 마킹하여 표시
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
          //앞의 녀석과 뒤의 녀석을 사이에 삽입

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

      /*
         만일 large 요청이라면, 정렬된 순서에서 현재 bin의 chunk를 통해 가장 작은 것을 찾기 위해 스캔, 이를 위해 skip list 사용
         large bin에서 가장 적합한 크기의 chunk를 찾아 재할당
       */

      if (!in_smallbin_range (nb))  //large bin
        {
          bin = bin_at (av, idx);

          /* 만일 chunk가 비었거나, 가장 큰 large chunk가 너무 작은 경우 스캔 스킵 */
          if ((victim = first (bin)) != bin &&
              (unsigned long) (victim->size) >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize; //자신보다 조금 작은 chunk
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;
              //작은 chunk부터 큰 chunk 순으로 적합한 chunk 탐색

              /* skip list를 다시 라우팅할 필요없도록 크기의 첫 번째 항목 제거 안 함  */
              if (victim != last (bin) && victim->size == victim->fd->size)
                victim = victim->fd;
              //최적의 chunk가 bin에서 가장 작은 chunk가 아니며, size가 바로 앞의 chunk의 크기와 동일한 경우 앞의 chunk 사용

              remainder_size = size - nb; //남는 크기 저장
              unlink (victim, bck, fwd);  // bin list에서 적합 chunk 제거

              /* 배출 */
              if (remainder_size < MINSIZE) //남은 크기가 최소 크기보다 작은 경우
                {
                  set_inuse_bit_at_offset (victim, size); // 대상 chunk+size의 위치에 있는 chunk의 size에 Prev_Inuse 설정
                  if (av != &main_arena)  // main arena가 아닌 경우
                    victim->size |= NON_MAIN_ARENA; //세팅
                }
              /* 분리 */
              else //남은 크기가 최소 크기보다 큰 경우
                {
                  remainder = chunk_at_offset (victim, nb);
                  //나머지 영역의 주소 저장
                  /* unsorted list가 비어 있다고 가정할 수 없으므로 여기에 완전한
                  삽입 수행*/
                  bck = unsorted_chunks (av); // unsorted chunk 헤더를 가져옴
                  fwd = bck->fd;  // 첫 번째 unsorted chunk 저장
	                  if (__glibc_unlikely (fwd->bk != bck)) // 이중 연결리스트 오류
                    {
                      errstr = "malloc(): corrupted unsorted chunks";
                      goto errout;
                    }
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  //나머지를 unsorted chunk의 시작 부분에 추가(FIFO)
                  if (!in_smallbin_range (remainder_size))  //large bin이라면
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  // 재할당되는 녀석의 특수 비트 설정
                  set_head (remainder, remainder_size | PREV_INUSE);
                  // 나머지 녀석의 특수 비트 설정
                  set_foot (remainder, remainder_size);
                  // remainder 다음 chunk의 이전 크기 재설정
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);   //재할당 완료
              return p;
            }
        }

      /*
         다음으로 큰 bin을 시작으로, bin을 스캔하여 chunk 검색.
         이 검색은 엄격한 최적 적합임; i.e., the smallest
         (가장 최근에 사용된 것과 연관성이 없는) chunk가 선택됨
         bitmap을 사용하면 대부분의 블록이 비어있지 않은지 확인하지 않아도 됨
         chunk가 반환되지 않은 앞의 단계에서 모든 bin을 건너뛰는 특수한 경우는 매우 빠르게 끝나버린다.
       */

      ++idx;  // large bin list index 값 증가
      bin = bin_at (av, idx);
      block = idx2block (idx);    // 해당 large bin list의 index 값에 맞는 블록 저장
      map = av->binmap[block];
      bit = idx2bit (idx);    //binmap의 매핑에서 특정 비트 추출

      for (;; )
        {
          /* 해당 블록에 더 이상 세팅된 비트가 없다면 나머지 블록은 스킵  */
          if (bit > map || bit == 0)
            {
              do
                { //map이 0이 될 때 까지(없을 때 까지)
                  if (++block >= BINMAPSIZE) /* out of bins */
                  //block이 binmap의 크기를 넘어갈 때 top chunk를 사용하러
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));
              //검색된 block에 맞는 index 위치의 bin list 획득
              bit = 1;
            }

          /* 설정된 bit로 bin으로 진행, bit는 반드시 1 이여야 함 */
          while ((bit & map) == 0)
            {
              bin = next_bin (bin);   // 다음 bin list 탐색
              bit <<= 1;
              assert (bit != 0);
            }

          /* bin이 비어있지 않은 것 같으므로 검사 */
          victim = last (bin);

          /*  비어있는 bin이 있다면 잘못된 경보이므로 bit 제거 */
          if (victim == bin)   //비어있음
            {
              av->binmap[block] = map &= ~bit; /* Write through(즉시 변경) */
              bin = next_bin (bin); //다음 bin list 저장
              bit <<= 1;
            }

          else
            {
              size = chunksize (victim);  //탐색된 chunk의 크기 저장

              /*  현재 bin에 있는 chunk가 사용하기에 충분히 큰지 확인 */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb; //나머지 값 저장

              /* unlink */
              unlink (victim, bck, fwd);  //재할당을 위해 bin list에서 제거

              /* 배출 */
              if (remainder_size < MINSIZE) //최소 크기보다 나머지가 작은 경우
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
                    victim->size |= NON_MAIN_ARENA;
                }

              /* 분리 */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
                  //나머지 영역의 주소 저장

                  /* unsorted list가 비어 있다고 가정할 수 없으므로 여기에
                  제대로 된 삽입 수행  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
	                  if (__glibc_unlikely (fwd->bk != bck))
                    {
                      errstr = "malloc(): corrupted unsorted chunks 2";
                      goto errout;
                    }
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  //나머지 영역을 unsorted chunk의 시작 부분에 삽입

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))  //할당된 크기가 small bin이라면
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                  //나머지 영역의 크기가large bin이라면
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);   // 재할당
              return p;
            }
        }

    use_top:
      /*
         매우 큰 요청이라면 top chunk를 분리해서 사용, 분리해서 사용하기 때문에
         최상의 최적 적합임
         top chunk는 필요에 따라 시스템 제한까지 필요한 만큼 크게 확장이 가능하기 때문에 다른 사용 가능한 chunk보다 훨씬 큼.
         malloc의 초기화 이후에는 top chunk는 항상 존재하고 있어야 한다. 그렇지 않을 경우는 이 과정에서 top chunk를 채움 (이유는 sysmalloc에 경계 확장을 넣기 위한 최소한의 공간이 필요할 수 있기 때문)
       */

      victim = av->top; // top chunk로 해결할 거임
      size = chunksize (victim);

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        { //top chunk가 충분히 크기를 제공해주기 충분한 경우
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;    // 분리해주고 남은 영역을 top chunk로 설정
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);
          //할당된 영역과 남은 영역의 특수 bit 세팅

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes); // top chunk를 분리하여 할당
          return p;
        }

      /* atomic ops를 사용하여 fast chunk를 제거할 때 모든 블록 크기에 대해 여기로 올 수 있음  */
      else if (have_fastchunks (av))  // fast chunk 존재
        {
          malloc_consolidate (av);  // fast chunk 병합
          /* 본래의 bin index의 위치로 복원 */
          if (in_smallbin_range (nb)) // 요청한 크기가 small bin인 경우
            idx = smallbin_index (nb);   // small bin의 위치로
          else
            idx = largebin_index (nb);  //아니라면 large bin의 위치로
        }

      /*
         시스템에 종속적인 경우를 처리하기 위한 요청
       */
      else // top chunk의 크기보다 큰 요청이므로 새로 할당할 필요가 있음
        {
          void *p = sysmalloc (nb, av);    // 시스템에 메모리 요구
          if (p != NULL)
            alloc_perturb (p, bytes); // 필요한 만큼의 새로운 메모리 할당
          return p;
        }
    }
}

/*
   ------------------------------ free ------------------------------------------------------------------------------------------------------------------------------------
 */

static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* size */
  mfastbinptr *fb;             /* fastbin 관련 */
  mchunkptr nextchunk;         /* 다음 연속된 chunk */
  INTERNAL_SIZE_T nextsize;    /* size */
  int nextinuse;               /* 다음 chunk가 사용된다면 true */
  INTERNAL_SIZE_T prevsize;    /* 연속된 이전 chunk의 크기 */
  mchunkptr bck;               /* 링킹용 기타 임시 포인터 */
  mchunkptr fwd;               /* 링킹용 기타 임시 포인터 */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p); // chunk 크기 획득

  /* 성능을 해치지 않는 작은 보안 검사 수행:
     할당자는 주소 공간의 끝에 절대 랩핑되지 않음
     따라서 우연히 또는 침입자의 공격에 의해 여기에 나타날 수 있는 일부
     크기 값을 제외 할 수 있음  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))  //size와 정렬 확인
    {
      errstr = "free(): invalid pointer";
    errout:
      if (!have_lock && locked)
        (void) mutex_unlock (&av->mutex); //unlock, 오류 반환
      malloc_printerr (check_action, errstr, chunk2mem (p));
      return;
    }
  /* 각 chunk의 크기는 최소 MINSIZE 이상이거나 MALLOC_ALIGNMENT의 배수임  */
    if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      errstr = "free(): invalid size";
      goto errout;
    }

     check_inuse_chunk(av, p);   // 사용 중인 chunk인지 확인

  /*
    fastbin에 chunk를 배치하기 적격한 경우, malloc에서 빨리 찾아 사용할 수
    있도록 배치
  */

    if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	     TRIM_FASTBINS가 설정되어 있는 경우, top chunk의 경계에 위치한 chunk를
       fastbin에 배치하면 안 됨
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	       || __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	/* lock이 없거나 system_mem의 동시 수정으로 긍정거부가 될 수 있음.
     lock을 다시 설정한 후, 테스트 수행  */
    	  if (have_lock
    	    || ({ assert (locked == 0);
    		  mutex_lock(&av->mutex);
    		  locked = 1;
    		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
          // p 다음 chunk가 최소 size보다 작거나
    		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
            //p 다음 chunk의 size가 System이 허용하는 메모리 크기보다 큰지
    	      }))
    	  {
    	    errstr = "free(): invalid next size (fast)";
    	    goto errout;
    	  }
    	  if (! have_lock)   // lock이 걸려있다면 해제
    	  {
    	    (void)mutex_unlock(&av->mutex);
    	    locked = 0;
    	  }
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);  //정리

    set_fastchunks(av); //Arena에 fastchunk flags 설정
    unsigned int idx = fastbin_index(size); // 크기에 맞는 index 선택
    fb = &fastbin (av, idx);  //fastbin list 가져옴

    /* P를 fastbin 내부에 연결 P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
      	/* bin의 상단부에 추가할 수 있는지 확인
      	   (i.e., double free).  */
      	if (__builtin_expect (old == p, 0))
        //free하고자 하는 chunk인 p가 fastbin list에 이미 저장되어 있는지
      	  {
      	    errstr = "double free or corruption (fasttop)";
      	    goto errout; //저장되어 있다면 double free bug
      	  }
      	/* 상단에 있는 fastbin chunk의 크기가 추가하고자 하는 chunk의 크기와
           같은지 체크. lock이 걸린 경우에만 old를 역 참조할 수 있으며, 그렇지
           않은 경우는 할당 자체가 취소되었을 것임. 실제 확인을 위해서는 아래의 old_idx 사용을 참고 */
      	if (have_lock && old != NULL)  // lock이 걸려있고, old가 존재하는 경우
      	  old_idx = fastbin_index(chunksize(old));
          //old의 chunk 크기에 맞는 fastbin list index를 가져옴
      	p->fd = old2 = old;
        // p->fd를 fastbin list의 chunk 주소로 변경(fastbin의 가장 앞 부분에 현재 chunk 삽입?)
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2); // fb의 값을 old2에서 p로 변경하고 old2 값을 반환

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
      	errstr = "invalid fastbin entry (free)";
      	goto errout;
      }
  } //fastbin에 p를 저장

  /*
    도착하지 않은 다른 chunk들은 통합
  */

  else if (!chunk_is_mmapped(p)) {  //mmap으로 할당된 chunk가 아니라면
    if (! have_lock) {  //unlock 상태인지 확인
      (void)mutex_lock(&av->mutex);
      locked = 1;   //lock 설정
    }

    nextchunk = chunk_at_offset(p, size); // 다음 chunk를 가져옴

    /* 간단한 테스트 : 블록이 이미 top block인지 체크  */
    if (__glibc_unlikely (p == av->top))   //p가 top chunk임
      {
      	errstr = "double free or corruption (top)";
      	goto errout;
      }
    /* 다음 chunk가 Arena의 경계를 넘어서는지 체크  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
      	errstr = "double free or corruption (out)";
      	goto errout;
      }
    /* block이 실제로 사용하고 있는 것인지 표시 확인 */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
    //현재 chunk가 이미 사용 안 하는 중
      {
      	errstr = "double free or corruption (!prev)";
      	goto errout;
      }
    /* 다음 chunk의 크기가 최소 크기보다 작거나 System이 허용하는 메모리보다
       큰지 확인 */
    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
      	errstr = "free(): invalid next size (normal)";
      	goto errout;
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    /* 뒤로 병합 */
    if (!prev_inuse(p)) { //이전 chunk가 사용하고 있지 않다면
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(p, bck, fwd);  //이전 청크를 병합해 제거
    }

    if (nextchunk != av->top) { // 다음 chunk가 top chunk가 아닌 경우
      /* inuse bit를 얻고 해제 */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
      // 다음 chunk가 사용 중인지 확인

      /* 앞으로 병합 */
      if (!nextinuse) { // 다음 chunk가 사용 중이지 않다면
      	unlink(nextchunk, bck, fwd); //제거
      	size += nextsize;
      } else
	    clear_inuse_bit_at_offset(nextchunk, 0); // 다음 chunk의 prev_inuse 제거

      /*
	chunk를 unsorted chunk list에 배치. chunk는 malloc에서 다시 사용할 기회가
  있을 때 까지는 unsorted bin에 저장되어 일반 bin으로는 가지 않는다.
      */

      bck = unsorted_chunks(av);  //unsorted bin의 헤더를 가져옴
      fwd = bck->fd;  // 첫 번째 unsorted bin을 가져옴
      if (__glibc_unlikely (fwd->bk != bck))
    	{
    	  errstr = "free(): corrupted unsorted chunks";
    	  goto errout;
    	}
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
    	{
    	  p->fd_nextsize = NULL;
    	  p->bk_nextsize = NULL;
    	}
      bck->fd = p;
      fwd->bk = p;  // unsorted bin의 맨 앞에 현재 chunk 저장(FIFO)

      set_head(p, size | PREV_INUSE); //prev_inuse 설정
      set_foot(p, size);  //다음 chunk의 prev_size 재설정

      check_free_chunk(av, p);  //제대로 해제가 되었는지 확인
    }

    /*
      만약 chunk가 현재 메모리의 끝과 경계를 가진다면 top chunk로 병합
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE); // prev_inuse 설정
      av->top = p;  // top chunk로 병합
      check_chunk(av, p);
    }

    /*
      큰 공간을 해제하는 경우, 왠만하면 주변 chunk를 전부 병합
      그 다음, 사용하지 않은 최상위 메모리가 trim 임계 값을 초과하는 경우,
      malloc_trim을 통해 top chunk의 크기 감소
      max_fast가 0이 아닌 경우, top chunk의 경계에 fastbin이 있는지 알 수 없기 때문에 fastbin을 통합하지 않으면 임계 값에 도달했는지 알 수 없음
      그러나 free로 각각을 병합을 하면 안 되므로 절충안으로
      FASTBIN_CONSOLIDATION_THRESHOLD에 도달하면 연결이 수행됨
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (have_fastchunks(av))  //fastbin이 존재한다면
	       malloc_consolidate(av); //fastbin을 병합 실시

      if (av == &main_arena) {  //현재 arena가 main_arena인 경우
#ifndef MORECORE_CANNOT_TRIM
      	if ((unsigned long)(chunksize(av->top)) >=
      	    (unsigned long)(mp_.trim_threshold))
          //top chunk가 trim의 임계값보다 큰 경우
      	  systrim(mp_.top_pad, av);
          //top chunk의 크기 감소
#endif
      } else {
      	/* top chunk가 크지 않더라도 해당 heap이 사라질 수 있으므로 항상 heap_trim() 수행  */
      	heap_info *heap = heap_for_ptr(top(av));
        //arena의 시작 포인터 가져옴

      	assert(heap->ar_ptr == av);
      	heap_trim(heap, mp_.top_pad);
      }
    }

    if (! have_lock) {  //lock이 걸려있지 않다면
      assert (locked);
      (void)mutex_unlock(&av->mutex); // unlock
    }
  } //sbrk로 할당한 경우 수행하는 부분
  /*
    chunk가 mmap을 통해 할당된 경우 munmap()을 통해 제거
  */
  else {  //mmap으로 할당된 경우
    munmap_chunk (p);
  }
}



#ifndef atomic_forced_read
# define atomic_forced_read(x) \
  ({ __typeof (x) __x; __asm ("" : "=r" (__x) : "0" (x)); __x; })
#endif

/* ----------- Routines dealing with system allocation -------------- */

/*
   sysmalloc은 시스템에서 더 많은 메모리를 필요로 하는 malloc 요청을 처리
   top chunk에게 요청한 크기를 처리할 충분한 공간이 없어 top chunk를 확장하거나
   대체해야 함
 */

static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* av->top에 들어있는 값 */
  INTERNAL_SIZE_T old_size;       /* size */
  char *old_end;                  /* end address */

  long size;                      /* 첫 MORECORE 또는 mmap call의 인자 */
  char *brk;                      /* MORECORE로부터의 return value */

  long correction;                /* 2nd MORECORE call의 인자 */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* 새로운 공간의 앞 부분에 사용할 수 없는 값 */
  INTERNAL_SIZE_T end_misalign;   /* 새로운 공간의 끝 부분에 남아있는 페이지 조각 */
  char *aligned_brk;              /* brk에 정렬된 오프셋 */

  mchunkptr p;                    /* 할당되거나 반환된 chunk */
  mchunkptr remainder;            /* 할당되고 남은 나머지 영역 */
  unsigned long remainder_size;   /* size */


  size_t pagemask = GLRO (dl_pagesize) - 1;
  bool tried_mmap = false;


  /*
     mmap을 가지고, 요청 크기가 mmap의 임계값을 충족하며, 시스템이 mmap을
     지원하면서 현재 할당된 매핑된 영역이 충분하지 않은 경우 top chunk를 확장하지
     않고 해당 요청을 직접 매핑
   */

  if ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold) &&
      (mp_.n_mmaps < mp_.n_mmaps_max))
    {
      char *mm;           /* mmap 호출로부터의 return value*/

    try_mmap:
      /*
         가장 가까운 페이지만큼 크기를 올림. mmap chunk의 경우, prev_size
         필드를 사용할 수 있는 다음 chunk가 없기 때문에, 오버헤드는 일반
         chunk보다 더 큰 1개의 SIZE_SZ unit임.
         아래의 front_misalign 처리를 참조해보면 glibc에 대해 높은 정렬을
         하지 않는 이상 추가적인 정렬이 필요가 없음
       */
      if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
        size = (nb + SIZE_SZ + pagemask) & ~pagemask;
      else
        size = (nb + SIZE_SZ + MALLOC_ALIGN_MASK + pagemask) & ~pagemask;
      tried_mmap = true;

      /* 크기가 0으로 감싸지는 경우 시행 안 함 */
      if ((unsigned long) (size) > (unsigned long) (nb))
        {
          mm = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));

          if (mm != MAP_FAILED)
            {
              /*
                 mmap으로 할당된 영역의 시작 오프셋은 chunk의 prev_size 필드에
                 저장, 이를 통해 여기와 memalign()에서 정렬 요구 사항을
                 충족시키도록 반환된 시작 주소를 조정할 수 있게 하며, free()와
                 realloc()에서 나중에 munmap에 대해 적절한 주소 인자를 계산할 수
                 있게 함
               */

              if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
                {
                  /* glibc의 경우, chunk2mem는 address를 2*SIZE_SZ와 2*SIZE_SZ-1인
                  MALLOC_ALIGN_MASK씩 증가시킴 . mmap으로 할당된 영역은 반드시 MALLOC_ALIGN_MASK로 정렬되어 페이지가 정렬되어 있음  */
                  assert (((INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK) == 0);
                  front_misalign = 0;
                }
              else
                front_misalign = (INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK;
              if (front_misalign > 0)
                {
                  correction = MALLOC_ALIGNMENT - front_misalign;
                  p = (mchunkptr) (mm + correction);
                  p->prev_size = correction;
                  set_head (p, (size - correction) | IS_MMAPPED);
                }
              else
                {
                  p = (mchunkptr) mm;
                  set_head (p, size | IS_MMAPPED);
                }

              /* 통계 업데이트 */

              int new = atomic_exchange_and_add (&mp_.n_mmaps, 1) + 1;
              atomic_max (&mp_.max_n_mmaps, new);

              unsigned long sum;
              sum = atomic_exchange_and_add (&mp_.mmapped_mem, size) + size;
              atomic_max (&mp_.max_mmapped_mem, sum);

              check_chunk (av, p);

              return chunk2mem (p); //새로운 영역 할당
            }
        }
    }

  /* 상단의 설정으로부터 기록 */

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));

  brk = snd_brk = (char *) (MORECORE_FAILURE);

  /*
     처음 호출하는게 아니라면, old_size는 최소한 MINSIZE 이상이 되어야 하고
     prev_inuse가 설정되어 있어야 함
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & pagemask) == 0));

  /* 전제 조건 : nb 요청을 충족시킬만큼의 충분한 공간이 현재 없음 */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));


  if (av != &main_arena)
    {
      heap_info *old_heap, *heap;
      size_t old_heap_size;

      /* 먼저, 현재 heap을 확장 */
      old_heap = heap_for_ptr (old_top);
      old_heap_size = old_heap->size;
      if ((long) (MINSIZE + nb - old_size) > 0
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
        {
          av->system_mem += old_heap->size - old_heap_size;
          arena_mem += old_heap->size - old_heap_size;
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE);
        }
      else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))
        {
          /* 새롭게 할당된 heap을 사용  */
          heap->ar_ptr = av;
          heap->prev = old_heap;
          av->system_mem += heap->size;
          arena_mem += heap->size;
          /* Set up the new top.  */
          top (av) = chunk_at_offset (heap, sizeof (*heap));
          set_head (top (av), (heap->size - sizeof (*heap)) | PREV_INUSE);

          /* fencepost를 설정하고 크기가 MALLOC_ALIGNMENT의 배수로 된 이전의
          top chunk를 해제 */
          /* 나중에 다시 top chunk가 될 수도 있기 때문에 fencepost는 최소
          MINSIZE 이상임. chunk가 사용 중이라고 표시되어 있으며, footer도
          설정되어 있음 */
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
        /* 메모리를 mmap하기 위해 사용 가능  */
        goto try_mmap;
    }
  else     /* av == main_arena */


    { /* nb + pad + overhead를 위한 충분한 공간 요청 */
      size = nb + mp_.top_pad + MINSIZE;

      /*
         연속적인 경우, 새로운 공간과 결합할 수 있는 기존 공간을 빼낼 수 있음.
          연속적인 공간을 실제로 얻지 못하는 경우에만 나중에 다시 추가
       */

      if (contiguous (av))
        size -= old_size;

      /*
         페이지 크기의 배수로 반올림
         MORECORE가 연속적이지 않다면, 전체 페이지 인수만으로 호출됨. MORECORE가
         인접해 있으며, 처음으로 호출하는 것이 아니라면 이전 호출의 페이지 정렬을
         유지. 그렇지 않은 경우는 아래의 페이지 정렬로 수정.
       */

      size = (size + pagemask) & ~pagemask;

      /*
         만일 인자가 너무 크거나 음수로 되어 있다면, MORECORE를 호출할 수 없음.
          mmap은 size_t를 인자로 취하기 때문에 MORECORE를 호출할 수 없는 경우에도
          아래의 과정을 성공적으로 수행할 수 있음
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
             mmap을 사용하는 경우, MORECORE가 실패하거나 사용할 수 없다면 백업으로
             사용. 연속적인 공간을 제공하기 위해 sbrk를 확장할 수는 없지만 다른 곳에서는 공간을 사용할 수 있기 때문에 주소 공간에 "holes"이 있는 시스템에서 할 가치가 있음. 이 때의 공간은 분리된 mmap 영역으로
             사용되지 않아 mmap의 최대 개수와 임계값 한계를 무시함
           */

          /* 이전 top과 병합할 수 없어 size를 다시 추가 */
          if (contiguous (av))
            size = (size + old_size + pagemask) & ~pagemask;

          /* mmap을 백업으로 사용한다면, 더욱 큰 단위로 사용 */
          if ((unsigned long) (size) < (unsigned long) (MMAP_AS_MORECORE_SIZE))
            size = MMAP_AS_MORECORE_SIZE;

          /* size가 0으로 감싸진다면 수행 안 함 */
          if ((unsigned long) (size) > (unsigned long) (nb))
            {
              char *mbrk = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));

              if (mbrk != MAP_FAILED)
                {
                  /* 다른 sbrk 호출을 사용할 필요가 없으며 사용할 수 없음 */
                  brk = mbrk;
                  snd_brk = brk + size;

                  /*
                     더 이상 인접한 sbrk 영역이 없다는 걸 기록함
                     어음에 mmap이 백업으로 사용된 이후에는 영역이 잘못 연결되어
                     있기 때문에 인접한 공간에 의존하지 않음
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
             MORECORE가 이전 공간을 확장하는 경우에는 마찬가지로 상단 크기도
              확장할 수 있음
           */

          if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE))
            set_head (old_top, (size + old_size) | PREV_INUSE);

          else if (contiguous (av) && old_size && brk < old_end)
            {
              /* Oops!  Someone else killed our space..  Can't touch anything.  */
              malloc_printerr (3, "break adjusted to free malloc space", brk);
            }

          /*
             그렇지 않은 경우에는 조정 필요 :
           * 만약 처음 호출하거나 연속적이지 않다면, sbrk를 호출하여 메모리의 끝
             부분을 찾음
           * malloc에서 반환된 모든 chunk가 MALLOC_ALIGNMENT을 만족하는지 확인
           * 만일 개입하고 있는 외부의 sbrk가 있는 경우에는, old_top의 기존 공간과
              새로운 공간을 결합할 수 없다는 점을 고려해 sbrk 크기 요청을 조정해야 함
           * 대부분의 시스템은 한 번에 전체 페이지를 내부적으로 할당하는데,
              이 경우 요청한 전체 페이지를 사용할 수 있음
              그래서 페이지 경계를 맞추기에 충분한 메모리를 할당하고 이후에는
              연속적인 호출로 페이지 정렬이 되게 됨
           */

          else
            {
              front_misalign = 0;
              end_misalign = 0;
              correction = 0;
              aligned_brk = brk;

              /* 연속된 경우 */
              if (contiguous (av))
                {
                  /* system_mem으로써 외부 sbrk 카운트 */
                  if (old_size)
                    av->system_mem += brk - old_end;

                  /* 이 공간에서 만들어진 첫 번째 새 chunk의 정렬 보장 */

                  front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                  if (front_misalign > 0)
                    {
                      /*
                         정렬된 위치에 도달하기 위해 일부 바이트 스킵
                         이렇게 낭비된 앞의 바이트는 특별히 표시할 필요 없음
                         av->top과 시작부터 생성된 모든 chunk의 prev_inuse는 초기화
                         이후에는 항상 true이므로 절대로 접근될 수 없음
                       */

                      correction = MALLOC_ALIGNMENT - front_misalign;
                      aligned_brk += correction;
                    }

                  /*
                     기존 공간에 인접하지 않다면 old_top 공간과 병합할 수 없기
                     때문에 추가적인 2차 요청을 해야함
                   */

                  correction += old_size;

                  /* 페이지 경계를 맞추기 위한 마지막 주소 확장 */
                  end_misalign = (INTERNAL_SIZE_T) (brk + size + correction);
                  correction += ((end_misalign + pagemask) & ~pagemask) - end_misalign;

                  assert (correction >= 0);
                  snd_brk = (char *) (MORECORE (correction));

                  /*
                     일치하도록 할당할 수 없다면, 적어도 현재의 brk를 탐색.
                     실패없이 진행하는 것만으로도 충분할 수 있음
                     2번째 sbrk가 실패하지 않은 경우, 첫 번째 sbrk와 공간이
                     연속되어 있다고 가정. 프로그램이 다중 스레드지만 lock을 사용하지 않고 첫 번째 호출과 2번째 호출 사이에 외부 sbrk가
                     발생하지 않는 한 안전하다고 가정함.
                   */

                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      correction = 0;
                      snd_brk = (char *) (MORECORE (0));
                    }
                  else
                    {
                      /* 필요한 경우 'morecore'hook을 호출.  */
                      void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
                      if (__builtin_expect (hook != NULL, 0))
                        (*hook)();
                    }
                }

              /* 연속되지 않은 경우의 처리문 */
              else
                {
                  if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
                    /* MORECORE/mmap은 올바르게 정렬해야 함 */
                    assert (((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0);
                  else
                    {
                      front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                      if (front_misalign > 0)
                        {
                          /*
                             정렬된 위치에 도달하기 위해 일부 바이트 스킵
                             낭비된 앞의 바이트를 특별히 표시할 필요 없음
                             av->top과 시작부터 생성된 모든 chunk의 prev_inuse는 초기화 이후에는 항상 true이므로 절대로 접근될 수 없음
                           */

                          aligned_brk += MALLOC_ALIGNMENT - front_misalign;
                        }
                    }

                  /* 현재 메모리의 끝 탐색 */
                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      snd_brk = (char *) (MORECORE (0));
                    }
                }

              /* 2번째 sbrk 결과를 기반으로 한 top 조정 */
              if (snd_brk != (char *) (MORECORE_FAILURE))
                {
                  av->top = (mchunkptr) aligned_brk;
                  set_head (av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
                  av->system_mem += correction;

                  /*
                     처음 호출하는게 아니라면, 외부 sbrk나 인접하지 않은
                     공간으로 인해 격차 발생 old_top에 이중 fencepost를 삽입해 소요하지 않은 공간과의 병합 방지 이 fencepost는 사용하지
                     않는 것으로 표시되어 있고 사용하기에는 너무나도 작은
                     인공적인 chunk임. 크기와 정렬을 만들기 위해서는 2 가지가 필요
                   */

                  if (old_size != 0)
                    {
                      /*
                         size_t size를 MALLOC_ALIGNMENT로 유지하면서 fencepost를
                          삽입하려면 old_top을 축소해야 함. 적어도 old_top에 충분한
                          공간이 있는 것을 알고 있으므로 문제 없음
                       */
                      old_size = (old_size - 4 * SIZE_SZ) & ~MALLOC_ALIGN_MASK;
                      set_head (old_top, old_size | PREV_INUSE);

                      /*
                         old_size가 이전에 MINSIZE였던 경우, 다음 할당은 old_top을
                         완전히 덮어쓰게 되는데, 이것은 의도적인 것임. old_top이
                         그렇지 않은 경우에는, fencepost가 필요
                       */
                      chunk_at_offset (old_top, old_size)->size =
                        (2 * SIZE_SZ) | PREV_INUSE;

                      chunk_at_offset (old_top, old_size + 2 * SIZE_SZ)->size =
                        (2 * SIZE_SZ) | PREV_INUSE;

                      /* 가능하면 나머지는 정리 */
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

  /* 마지막으로 할당 실시 */
  p = av->top;
  size = chunksize (p);

  /* 위의 할당 경로 중 하나가 성공했는지 확인 */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p); // 새 영역 반환
    }

  /* 모든 실패 경로 캐치 */
  __set_errno (ENOMEM);
  return 0;
}

/*
   systrim()은 sysmalloc()의 역순임. malloc pool의 높은 주소의 끝 부분에 사용되지 않은 메모리가 있으면 sbrk에 대해 음수 인자를 통해 시스템에 메모리를 다시 할당함. 상단의 공간이 trim의 임계값을 초과하면 free()에 의해
   자동으로 호출됨. 또한 public malloc_trim 루틴에 의해서도 호출됨. 실제로
   메모리를 해제하면 1을 반환하고 그렇지 않은 경우 0을 반환함
 */

static int
systrim (size_t pad, mstate av)
{
  long top_size;         /* top chunk의 메모리 크기 */
  long extra;            /* 해제할 크기 */
  long released;         /* 실제로 해제된 크기*/
  char *current_brk;     /* sbrk call의 사전 점검으로써 반환된 address */
  char *new_brk;         /* sbrk call의 사후 점검으로써 반환된 address */
  size_t pagesz;
  long top_area;

  pagesz = GLRO (dl_pagesize);
  top_size = chunksize (av->top);   // top chunk의 크기 저장

  top_area = top_size - MINSIZE - 1;  //chunk 정보를 저장하기 위한 공간 제외
  if (top_area <= pad)
    return 0;

  /* 적어도 하나의 페이지를 유지한 채, 페이지 단위로 해제 */
  extra = (top_area - pad) & ~(pagesz - 1);

  if (extra == 0)
    return 0;

  /*
     메모리의 끝을 마지막으로 세팅한 경우에만 진행
     이렇게 할 경우, 외부 sbrk 호출이 있더라도 문제가 발생하지 않음
   */
  current_brk = (char *) (MORECORE (0));
  // sbrk로 살짜 건드려서 top chunk + top_size의 주소 확인
  if (current_brk == (char *) (av->top) + top_size)
    {
      /*
         메모리를 해제할 거임. MORECORE로 반환된 값은 무시하고 그 대신,
         메모리의 새로운 끝 부분을 찾기 위해 다시 호출할 것임.
         이렇게 하면 첫 호출에서 우리가 요청한 것보다 적은 양으로 brk 값이
         변경된 경우 문제가 발생하지 않음.(brk를 좋지 않은 방식으로 변경한다면
         문제가 발생할 수 있지만 조정 가능함. 조정으로 인해 다운스트림 오류가
         발생할 수도 있음)
       */

      MORECORE (-extra);  // 음수 값으로 sbrk 호출
      /* 필요한 경우, MORECORE hook 호출  */
      void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
      if (__builtin_expect (hook != NULL, 0))
        (*hook)();
      new_brk = (char *) (MORECORE (0));  // 다시 건드려봄

      LIBC_PROBE (memory_sbrk_less, 2, new_brk, extra);

      if (new_brk != (char *) MORECORE_FAILURE) // 제대로 성공한 경우
        {
          released = (long) (current_brk - new_brk);  //해제된 크기 확인

          if (released != 0)
            {
              /* 해제 성공, top 조정 */
              av->system_mem -= released;
              //system_mem에서 해제된 크기 감소
              set_head (av->top, (top_size - released) | PREV_INUSE);
              //top chunk에 새롭게 prev_inuse 설정
              check_malloc_state (av);
              //상태 확인
              return 1; //top chunk를 축소 성공
            }
        }
    }
  return 0;
}

// mmap으로 할당된 chunk를 해제하기 위한 함수
static void
internal_function
munmap_chunk (mchunkptr p)
{
  INTERNAL_SIZE_T size = chunksize (p); // chunk의 size 저장

  assert (chunk_is_mmapped (p));  //mmap으로 할당된 chunk가 아니면 오류

  uintptr_t block = (uintptr_t) p - p->prev_size; // 이전 chunk의 주소 획득
  size_t total_size = p->prev_size + size;  // 이전 chunk와 현재 chunk의 크기

  /* 안타깝게도 여기서는 컴파일러 작업이 필요함. 일반적으로 페이지 크기에
     따라 BLOCK 및 TOTAL-SIZE를 개별적으로 테스트함. 하지만 gcc는 최적화
     가능성을 인식하지 못 하기 때문에 비트 테스트 이전에 두 값을 하나로 결합
     */
  if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
    {
      malloc_printerr (check_action, "munmap_chunk(): invalid pointer",
                       chunk2mem (p));
      return;
    }

  atomic_decrement (&mp_.n_mmaps);
  atomic_add (&mp_.mmapped_mem, -total_size);

  /* munmap이 실패하면 프로세스의 가상 메모리 주소 공간의 형태가 안 좋은
     형태로 변형됨. block을 붙여두면 처리가 거의 끝나지 않기 때문에 금방
     종료됨  */
  __munmap ((char *) block, total_size);
}
