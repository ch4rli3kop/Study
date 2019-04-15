본 포스팅은 https://sourceware.org/glibc/wiki/MallocInternals를 바탕으로 서술되었습니다.

# Overview of Malloc

GNU C library(glibc)의 malloc library는 어플리케이션에 할당된 메모리 주소 공간을 관리할 수 있는 함수들을 포함하고 있습니다. glibc malloc은 dlmalloc (Doug Lea malloc)에서 유래한 ptmalloc (pthreads malloc)으로부터 생성되었습니다. 이 glibc malloc을 "heap" 스타일 malloc이라고 하며, 넓은 메모리 영역(heap 영역) 안에서 다양한 크기를 가진 chunks가 존재하도록 하는 형식입니다. 과거에는 하나의 어플리케이션마다 오직 하나의 heap만이 존재할 수 있었지만, glibc malloc을 통해 하나의 어플리케이션이 복수 개의 heap을 가질 수 있게 되었고, 각 각의 heap은 해당 영역에서 사용될 수 있게 되었습니다.



용어 정리:

Arena

​	









```
gdb-peda$ x/10gx 0x7f2b524728d8
0x7f2b524728d8 <_IO_stdfile_0_lock+8>:	0x0000000000000000	0x0000000000000000
0x7f2b524728e8 <__free_hook>:	0x0000000000000000	0x0000000000000000
0x7f2b524728f8 <next_to_use>:	0x0000000000000000	0x0000000000000000
0x7f2b52472908 <disallow_malloc_check>:	0x0000000000000000	0x0000000000000000
0x7f2b52472918 <list_lock>:	0x0000000000000000	0x0000000000000000
```





```shell
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ ./thread_arena 
Welcome to per thread arena example::7399
Before malloc in main thread

...
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ cat /proc/7399/maps
56446d224000-56446d225000 r-xp 00000000 08:01 1054898                    /thread_arena
56446d424000-56446d425000 r--p 00000000 08:01 1054898                    /thread_arena
56446d425000-56446d426000 rw-p 00001000 08:01 1054898                    /thread_arena
56446e22b000-56446e24c000 rw-p 00000000 00:00 0                          [heap]
...libc.so
7f553bd20000-7f553bd24000 rw-p 00000000 00:00 0 
...libpthread.so
7f553bf3f000-7f553bf43000 rw-p 00000000 00:00 0 
...ld
7f553c151000-7f553c156000 rw-p 00000000 00:00 0 
...ld
7f553c16c000-7f553c16d000 rw-p 00000000 00:00 0 
7fff2231e000-7fff2233f000 rw-p 00000000 00:00 0                          [stack]
7fff22376000-7fff22379000 r--p 00000000 00:00 0                          [vvar]
7fff22379000-7fff2237b000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```



```shell
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ ./thread_arena 
Welcome to per thread arena example::7399
Before malloc in main thread

After malloc and before free in main thread

...
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ cat /proc/7399/maps
56446d224000-56446d225000 r-xp 00000000 08:01 1054898                    /thread_arena
56446d424000-56446d425000 r--p 00000000 08:01 1054898                    /thread_arena
56446d425000-56446d426000 rw-p 00001000 08:01 1054898                    /thread_arena
56446e22b000-56446e24c000 rw-p 00000000 00:00 0                          [heap]

7f553bd20000-7f553bd24000 rw-p 00000000 00:00 0 

7f553bf3f000-7f553bf43000 rw-p 00000000 00:00 0 

7f553c16c000-7f553c16d000 rw-p 00000000 00:00 0 
7fff2231e000-7fff2233f000 rw-p 00000000 00:00 0                          [stack]
7fff22376000-7fff22379000 r--p 00000000 00:00 0                          [vvar]
7fff22379000-7fff2237b000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```





```shell
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ ./thread_arena 
Welcome to per thread arena example::7399
Before malloc in main thread

After malloc and before free in main thread

After free in main thread

...
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ cat /proc/7399/maps
56446d224000-56446d225000 r-xp 00000000 08:01 1054898                    /thread_arena
56446d424000-56446d425000 r--p 00000000 08:01 1054898                    /thread_arena
56446d425000-56446d426000 rw-p 00001000 08:01 1054898                    /thread_arena
56446e22b000-56446e24c000 rw-p 00000000 00:00 0                          [heap]

7f553bd20000-7f553bd24000 rw-p 00000000 00:00 0 

7f553bf3f000-7f553bf43000 rw-p 00000000 00:00 0 

7f553c16c000-7f553c16d000 rw-p 00000000 00:00 0 
7fff2231e000-7fff2233f000 rw-p 00000000 00:00 0                          [stack]
7fff22376000-7fff22379000 r--p 00000000 00:00 0                          [vvar]
7fff22379000-7fff2237b000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```



```shell
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ ./thread_arena 
Welcome to per thread arena example::7399
Before malloc in main thread

After malloc and before free in main thread

After free in main thread

Before malloc in thread 1

...
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ cat /proc/7399/maps
56446d224000-56446d225000 r-xp 00000000 08:01 1054898                    /thread_arena
56446d424000-56446d425000 r--p 00000000 08:01 1054898                    /thread_arena
56446d425000-56446d426000 rw-p 00001000 08:01 1054898                    /thread_arena
56446e22b000-56446e24c000 rw-p 00000000 00:00 0                          [heap]
*7f553b132000-7f553b133000 ---p 00000000 00:00 0 
*7f553b133000-7f553b933000 rw-p 00000000 00:00 0 

7f553bd20000-7f553bd24000 rw-p 00000000 00:00 0 

7f553bf3f000-7f553bf43000 rw-p 00000000 00:00 0 

7f553c16c000-7f553c16d000 rw-p 00000000 00:00 0 
7fff2231e000-7fff2233f000 rw-p 00000000 00:00 0                          [stack]
7fff22376000-7fff22379000 r--p 00000000 00:00 0                          [vvar]
7fff22379000-7fff2237b000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```



```shell
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ ./thread_arena 
Welcome to per thread arena example::7399
Before malloc in main thread

After malloc and before free in main thread

After free in main thread

Before malloc in thread 1

After malloc and before free in thread 1

...
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ cat /proc/7399/maps
56446d224000-56446d225000 r-xp 00000000 08:01 1054898                    /thread_arena
56446d424000-56446d425000 r--p 00000000 08:01 1054898                    /thread_arena
56446d425000-56446d426000 rw-p 00001000 08:01 1054898                    /thread_arena
56446e22b000-56446e24c000 rw-p 00000000 00:00 0                          [heap]
*7f5534000000-7f5534021000 rw-p 00000000 00:00 0 
*7f5534021000-7f5538000000 ---p 00000000 00:00 0 
7f553b132000-7f553b133000 ---p 00000000 00:00 0 
7f553b133000-7f553b933000 rw-p 00000000 00:00 0 

7f553bd20000-7f553bd24000 rw-p 00000000 00:00 0 

7f553bf3f000-7f553bf43000 rw-p 00000000 00:00 0 

7f553c16c000-7f553c16d000 rw-p 00000000 00:00 0 
7fff2231e000-7fff2233f000 rw-p 00000000 00:00 0                          [stack]
7fff22376000-7fff22379000 r--p 00000000 00:00 0                          [vvar]
7fff22379000-7fff2237b000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

```



```shell
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ ./thread_arena 
Welcome to per thread arena example::7399
Before malloc in main thread

After malloc and before free in main thread

After free in main thread

Before malloc in thread 1

After malloc and before free in thread 1

After free in thread 1

...
ch4rli3kop@ubuntu:~/TestBox/malloc_thread_arena$ cat /proc/7399/maps
56446d224000-56446d225000 r-xp 00000000 08:01 1054898                    /thread_arena
56446d424000-56446d425000 r--p 00000000 08:01 1054898                    /thread_arena
56446d425000-56446d426000 rw-p 00001000 08:01 1054898                    /thread_arena
56446e22b000-56446e24c000 rw-p 00000000 00:00 0                          [heap]
7f5534000000-7f5534021000 rw-p 00000000 00:00 0 
7f5534021000-7f5538000000 ---p 00000000 00:00 0 
7f553b132000-7f553b133000 ---p 00000000 00:00 0 
7f553b133000-7f553b933000 rw-p 00000000 00:00 0 

7f553bd20000-7f553bd24000 rw-p 00000000 00:00 0 

7f553bf3f000-7f553bf43000 rw-p 00000000 00:00 0 

7f553c16c000-7f553c16d000 rw-p 00000000 00:00 0 
7fff2231e000-7fff2233f000 rw-p 00000000 00:00 0                          [stack]
7fff22376000-7fff22379000 r--p 00000000 00:00 0                          [vvar]
7fff22379000-7fff2237b000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```



fastbin에 들어가는 chunk인 경우 PREV_INUSE bit가 늘 세팅됨.

top chunk의 PREV_INUSE bit는 늘 세팅됨.



small bin chunk가 unsorted bin에 존재할 때, 또 다른 small bin chunk가 free 되면 계속해서 unsorted bin에 추가되지만, small bin이지만 다른 size를 가진 chunk가 free되거나, fastbin 같은 다른 chunk가 free 되면 small bin으로 옮긴다.

small bin chunk는 일반적으로 인접 chunk와 모두 결합하긴 하지만, fast, *unsorted, in use chunk와 인접해 있는 경우에는 병합하지 않아, 인접 chunk가 존재할 수도 있음



large bin의 경우, 크기별로 정렬이 되는데, free되는 chunk와 같은 size의 chunk가 이미 존재하는 경우,  새로 추가되는 chunk는 fd_nextsize와 bk_nextsize 필드는 사용하지 않고, 동일 size의 이전 chunk와 fd, bk만 이어준다. 따라서 요청 size에 대해서 첫 번째 chunk를 리턴하지 않고, 두 번째 chunk를 리턴한다. (fd_nextsize, bk_nextsize 포인터를 다시 이어줘야 하기 때문에 번거로움.)



circular doubly linked list

fastbin 범위에 속하지 않는 chunk일 경우, free 시 unsorted bin에 들어가기 때문에, `<main_arena+88>`을 가리키는 fd/bk가 생성된다. 그렇지만 `<main_arena+88>`은 top chunk인데, 이는 mchunkptr을 가리키기 때문며, + 0x10을 하면 unsorted bin( bins[0] )이 나타난다. fastbin의 경우 main_arena를 가리키지 않으며, 두 개를 free해야 첫 번째 free'd chunk에 fd가 생성된다.



libc 버전마다 구조체 멤버가 조금씩 다르므로 fake arena를 구성하는 경우 주의해야 한다. 따라서 `<main_arena+88>`이 항상 `top ptr`인 것은 아니다.



chunk의 size를 결정할 때, 무조건 0x10 bytes를 붙이는 게 아니라, 먼저 0x8 bytes를 확보한 뒤, align을 진행한다. 따라서, 64bit os 기준으로 24 bytes 만큼 요청하면 24+8 = 32 이므로, 0x10의 배수가 된다. 따라서 align 시 추가되는 bytes가 없어 0x21이 된다.



heap memory가 부족한 경우, malloc 은 내부적으로 brk나 mmap syscall을 사용하여 메모리 공간을 할당한다.

MMAP_THRESHOLD가 넘는 크기의 할당을 요청하는 경우 : mmap
mmap을 사용하여 아예 다른 곳에 메모리를 할당한다.
MMAP_THRESHOLD 값이 따로 설정되지 않은 경우에는 dynamic하게 결정된다.
free 시에는 munmap 을 호출한다.



작은 크기를 요청했는데, arena에 공간이 부족한 경우 : brk
brk는 program break의 위치를 변경해서 data segment size를 조정하는 syscall이다,
** program break는 uninitialized data segment의 끝 바로 다음 위치를 의미한다.
이를 이용하여 top chunk의 크기를 증가시켜 여분의 공간을 확보하거나 줄일 수 있다.
free 시에도 brk를 사용한다.



largebin 요청을 받으면 fastbin chunk를 다 합쳐서 unsorted bin으로 보내버림.









#### malloc sequence

```shell
1. 너무 큰 heap memory 할당을 요청하는 경우, mmap()을 사용하여 아예 다른 곳의 공간을 할당한다. MMAP_THRESHOLD 값으로 비교
2. fastbin에 요청에 맞는 chunk가 있는 경우 리턴
3. smallbin에 요청에 맞는 chunk가 있는 경우 리턴
4. large bin request일 경우, 모든 fastbin chunks들을 적당히 합치면서 unsorted bin으로 옮김.
5. unsorted bin에 있는 chunk들을 적당히 합치면서 small/large bin으로 옮김. 적당한 size의 chunk가 있는 경우 리턴.
6. 요청이 큰 경우, large bin을 탐색함.
7. 필요하다면 top chunk를 증가시키고(brk), top chunk를 잘라 리턴.
```

4, 5번에서 fastbin chunk는 결국 small/large bin으로 옮겨지게 되는데, chunk가 합쳐지지 않은 경우 그 크기 그대로 small bin chunk에 들어가게 된다.



#### free sequence

free 라는 것은 다른 application이 사용할 수 있도록 OS로 메모리를 반환하는 것이 아니라, 해당 chunk가 app 내에서 다시 사용될 수 있도록 free to be reused 상태임을 표시해주는 것이다. 다만, top chunk가 충분히 크다면 일부는 unmap 되어 OS로 반환될 수 있다.

```shell
1. fastbin size에 속하는 경우, fastbin에 추가한다.
2. mmapped chunk라면 munmap한다.
3. prev_inuse가 unset이면(인접한 chunk가 free 상태이면), 인접한 다른 free chunk와 합친다.
4. 이 chunk가 top chunk인 경우를 제외하고, chunk를 unsorted list에 위치시킨다. top chunk인 경우 top을 감소시킨다. brk
5. chunk가 충분히 크다면, fastbins와 합치고 system에 메모리를 반환할 수 있을 만큼 top chunk가 충분히 큰지 확인한다. 연기되었다가 다른 call이 수행되는 동안 진행될 수 있음
```



#### malloc 함수 호출 순서 : libc_malloc() -> int_malloc() -> sysmalloc()

1. libc_malloc() 함수에서 사용하는 Thread에 맞게 Arena를 설정한 후, int_malloc() 함수 호출

2. int_malloc() 함수에서는 재사용할 수 있는 bin을 탐색하여 재할당하고, 마땅한 bin이 없다면, top chunk에서 분리해서 할당함

3. top chunk가 요청한 크기보다 작은 경우, sysmalloc() 함수 호출

4. sysmalloc() 함수를 통해 시스템에 메모리를 요청해서 top chunk의 크기를 확장하고 대체함

   sysmalloc() 함수는 기존의 영역을 해제한 후, 새로 할당한다.



#### free 함수 호출 순서 : libc_free() -> int_free() -> systrim() or heap_trim() or munmap_chunk()

1. libc_free() 함수에서 mmap으로 할당된 메모리인지 확인 후, 맞을 경우 munmap_chunk() 함수를 통해 메모리 해제
2. 아닌 경우, 해제하고자 하는 chunk가 속한 arena의 포인터를 획득한 후, int_free() 호출
3. chunk를 해제한 후, 크기에 맞는 bin을 찾아 저장하고 top chunk와 병합을 할 수 있다면 병합 수행
4. 병합된 top chunk가 너무 커서 arena의 크기를 넘어선 경우, top chunk의 크기를 줄이기 위해 systrim() 함수 호출
5. 문제가 없다면, heap_trim() 함수 호출
6. mmap으로 할당된 chunk라면 munmap_chunk() 호출

## Malloc Internal fuctions

다음은 내부적으로 사용되는 일반 함수들을 나타낸다. 몇 몇 함수들은 사실 `#define`을 사용하여 정의된 것에 주목하라. 따라서 call parameters에 대한 변화는 사실 call 이후에도 유지된다. 또한, MALLOC_DEBUG가 설정되지 않은 것으로 가정하겠다.

#### arena_get (ar_ptr, size)

arena 정보를 얻을 수 있고, 해당 arena의 mutex를 lock한다. `ar_ptr`은 arena를 가리킨다. `size`는 어느 정도 크기의 메모리가 지금 당장 필요한지에 대한 힌트일 뿐이다.

#### sysmalloc [TODO]

시스템으로부터 더 많은 메모리를 필요로 하는 malloc case를 처리한다. entry 상에서, av->top(arena의 top chunk)가 nb bytes에 대한 서비스 요청에 충분한 공간을 가지지 못할 경우, av->top은 확장되거나 대체해야한다.



```c
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
```

#### void alloc_perturb (char *p, size_t n)

`perturb_byte` (`M_PERTURB`를 사용하는 malloc의 tunable한 매개 변수)가 0이 아닌 경우(default 0), `p`가 가리키는 n bytes를 `perturb_byte ^ 0xff`로 설정한다.

#### void free_perturb (char *p, size_t n)

`perturb_byte` (`M_PERTURB`를 사용하는 malloc의 tunable한 매개 변수)가 0이 아닌 경우(default 0), `p`가 가리키는 n bytes를 `perturb_byte`로 설정한다.





#### void malloc_init_state (mstate av)

malloc_state 구조체를 초기화한다. malloc_consolidate 내에서만 호출되며 동일한 context 내에서 불려져야 한다. 일부 최적화 컴파일러가 모든 호출 지점에서 인라인을 시도하는 경우가 있기 때문에(최적화가 아님), malloc_consolidate 외부에서는 호출하지 않게 한다. (malloc_consolidate 내에서의 인라인은 ㄱㅊ.) malloc_init_state에서는 다음과 같은 일을 수행한다.

1. fast bins가 아닌 bins들에 대해서, 빈 순환 linked list를 만듬.

2. av->flags 에 FASTCHUNKS_BIT 설정.

   ```c
   av->flags |= FASTCHUNKS_BIT; (version < libc 2.26)
   atomic_store_relaxed (&av->have_fastchunks, false); (version >= 2.26)
   ```

3. `av->top`을 `first unsorted chunk`로 초기화



#### unlink (AV, P, BK, FD)

본 함수는 bin에서 chunk를 제거하는 define된 매크로 함수이다.

1. chunk size가 next chunk에 설정된 previous size와 동일한지 확인한다. 그렇지 않다면, error("corrupted size vs. prev_size")가 발생한다.
2. `P->fd->bk == P`인지와 `P->bk->fd == P`인지를 확인한다. 그렇지 않다면, error("corrupted double-linked list")가 발생한다.
3. 제거를 용이하게 할 수 있도록, list 상에서 인접한 chunk들의 fd와 bk를 조정한다.
   1. Set `P->fd->bk` = `P->bk`.
   2. Set `P->bk->fd` =`P->fd`.



#### void malloc_consolidate(mstate av)

본 함수는 free() 함수의 특정 버전이다.

1. `global_max_fast` (fast bin에서 처리되는 메모리의 최대 크기) 값이 0인지(av가 초기화되지 않은 경우) 아닌지 확인. 값이 0이라면(av가 초기화가 되지 않은 경우), av를 인자로 하여 malloc_init_state를 호출한다.

2. `global_max_fast`가 0이 아니라면, av의 `FASTCHUNKS_BIT`를 없애버린다.(malloc_consolidate 과정을 진행하며 fastbin이 다 사라지기 때문.)

3. 다음 과정을 fastbin 배열의 처음부터 마지막까지 반복한다.

   1. 현재 fastbin chunk에 lock을 걸고, null아 아니면 이하 과정을 계속 수행한다.
   2. previous chunk(in memory)가 사용 중(prev_inuse bit)이 아니라면, previous chunk에 대해 `unlink`를 호출한다.
   3. next chunk(in memory)가 top chunk가 아니라면:
      1. next chunk가 사용 중이 아니라면, next chunk에 대해 unlink를 호출한다.
      2. 현재 chunk를 free된 상태의 previous, next chunk(in memory)와 병합하고, 병합된 chunk를 unsorted bin의 head에 추가한다. 
   4. next chunk(in memory)가 top chunk라면, chunk들을 적절하게 top chunk로 병합시킨다.

   

   NOTE : 'in use' 체크는 prev_inuse bit으로 체크하기 때문에, fastbin chunk는 free되었다고 고려되지 않음. (fastbin은 늘 prev_inuse가 세팅됨.)




#### mallopt()

이 함수는 malloc() 시 동작을 제어하는 다음과 같은 매개 변수들을 조정할 수 있다.

- M_MXFAST : fastbin의 최대 크기이다. 기본 값은 64로 설정되어 있으며 최대 80까지 늘릴 수 있다. 이 크기는 malloc 시 주어지는 인자에 대한 것이며, 실제 chunk의 크기는 header가 붙어 이보다 더 커진다.
- M_TRIM_THRESHOLD : free() 호출 시 병합된 chunk의 크기가 이 값보다 커지면 자동으로 sYSTRIm() 함수를 호출한다. 기본 값은 128KB이다.
- M_TOP_PAD : top chunk가 기본적으로 유지하는 여유 공간의 크기이다. sYSMALLOc()을 통해 top chunk의 크기를 늘릴 때나 free() 시 sYSTRIm()이 top chunk의 크기를 줄일 때 사용하며, 기본 값은 128KB이다.
- M_MMAP_THRESHOLD : sYSMALLOc()을 통해 시스템에 메모리 할당을 요청할 때 원하는 chunk의 크기가 이 값보다 크다면 sbrk() 대신 mmap()을 이용하여 할당한다. 기본 값은 128KB이다.
- M_MMAP_MAX : mmap()을 이용하여 할당할 수 있는 chunk의 최대 개수이다. 기본값은 64K이다.
- M_CHECK_ACTION : 메모리 할당 오류 시 취할 행동을 결정한다. 이 값이 5이면 간단한 메시지 만을 출력하고 NULL을 반환한다. 그렇지 않고 최하위 (0번) 비트가 설정되어 있으면 자세한 메시지를 출력하고 NULL을 반환한다. 그렇지 않고 1번 비트가 설정되어 있으면 abort()를 호출하여 프로세스를 바로 종료한다. 아무 비트도 설정되지 않았으면 단순히 NULL을 반환한다. 기본 값은 3이다.
- M_PERTURB : 메모리 테스트를 위한 패턴을 지정한다. 이 값이 0이 아니면 새로 할당된 메모리 영역을 모두 이 값을 이용하여 채운다. 기본 값은 0이다.



이러한 매개 변수는 mallopt()를 조정하지 않고도 환경 변수 설정을 이용해서 바꿀 수도 있음. (M_MXFAST 제외) 환경 변수의 이름은 M_MMAP_MAX 대신 MALLOC_MMAP_MAX와 같이 사용하면 된다.



## Core functions

요기가 malloc, free 함수의 핵심이다.

#### __libc_malloc (size_t bytes)

1. `mstate` 포인터를 얻기 위해 `arena_get`을 호출한다.
2. arena의 포인터와 size를 인자로 `_int_malloc`을 호출한다.
3. arena의 lock을 해제한다.
4. chunk에 대한 포인터를 리턴해주기 전에, 다음 중 하나를 만족해야 한다.
   - 리턴된 포인터가 NULL
   - chunk가 MMAPPED 됨.
   - chunk의 arena가 1에서 찾은 것과 동일해야 함.





#### checked_request2size

```c
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */
#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=                                                      \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))
/* pad request bytes into a usable size -- internal version */
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
/* Same, except also perform an argument and result check.  First, we check
   that the padding done by request2size didn't result in an integer
   overflow.  Then we check (using REQUEST_OUT_OF_RANGE) that the resulting
   size isn't so large that a later alignment would lead to another integer
   overflow.  */
#define checked_request2size(req, sz) \
({                                    \
  (sz) = request2size (req);            \
  if (((sz) < (req))                    \
      || REQUEST_OUT_OF_RANGE (sz)) \
    {                                    \
      __set_errno (ENOMEM);            \
      return 0;                            \
    }                                    \
})
```

checked_request2size(bytes, nb) 형태로 사용되는데, bytes는 사용자가 요청했던 size가 저장되어있는 변수이다. nb에 size + 0x8 한 뒤, align 과정을 진행한 값을 저장한다. 









#### void * _int_malloc(mstate av, size_t bytes)

1. checked_request2size 함수를 통해서 요청한 크기를 chunk 크기에 맞춘다. x64 기준으로 8bytes를 더한 후 align(0x10의 배수)에 맞추어 계산한다. 이 후 chunk의 크기는 이 값으로 사용한다.

2. 사용 가능한 arena가 존재하지 않은 경우(av == NULL), mmap을 사용하여 chunk를  얻기 위해 sysmalloc을 호출한다. sysmalloc을 이용하여 메모리를 할당받는데에 성공하면 alloc_perturb를 호출하여 메모리를 초기화한 뒤, 포인터를 반환한다. (종료)

3. size가 포함되는 범위에 따라 다음과 같이 나뉘어 동작한다.

   - size가 fastbin 범위인 경우
     1. 요청된 size에 따라서 적절한 bin에 접근하기 위해 fastbin array의 index를 가져온다.
     2. arena와 index를 이용하여 해당 size에 맞는 bin list의 주소를 가져온다.
     3. 해당 bin list의 첫 번째(가장 앞 쪽, HEAD) chunk를 victim에 저장한다.
     4. `victim`이 NULL이면(해당 fastbin list에 freed chunk가 없는 경우) 다음 단계로 넘어간다. (break and go to smallbin)
     5. (victim이 NULL이 아닌 경우) victim을 해당 fastbin list에서 제거한다. *fb == victim인지 확인하고 맞다면 *fb = victim->fd 한다. (fastbin 업데이트, LIFO 방식으로 동작)
     6. 꺼내온 victim의 size가 실제 그 bin에 맞는 크기인지 체크한다. (fastbin에서의 크기 검사) 그렇지 않으면 error("malloc(): memory corruption (fast)")를 발생시킨다.
     7. `alloc_perturb`를 호출하여 메모리를 초기화 한 뒤, 해당 포인터를 반환한다. (종료)

   - size가 smallbin 범위 :

     1. 요청된 size에 따라서 적절한 bin에 접근하기 위해 smallbin array의 index를 가져온다. (주어진 크기에 맞는 small bin의 인덱스를 계산하여 idx 지역변수에 저장한다.)

     2. `bin->bk != bin`을 비교하는데, 이 작업을 통해 해당 인덱스 내에 가장 오래된 chunk를 `victim` 지역 변수에 저장되고(FIFO), victim이 bin 자신을 가리키는지 여부에 따라 이 bin에 chunk가 존재하는지 아닌지 확인할 수 있다. (초기화 과정에서 각 bin list는 자기 자신을 가리키도록 설정되기 때문. fd는 mchunkptr을 가리키므로 fd 주소 + 0x10을 가리킴) chunk가 존재하지 않다면, 다음 단계(large bin)으로 넘어간다.

     3. 만약 `victim`이 NULL이라면(`initialization` 과정에서 발생, null인 경우 최초로 malloc() 함수가 호출된 경우이며, 아직 초기화가 제대로 이루어지지 않았으므로 malloc_init_state() 내부 함수를 호출하여 초기화를 수행한다.), `malloc_consolidate`를 호출하고, 다음 단계(large bin)으로 넘어간다.

     4. 그렇지 않고 `victim`이 NULL이 아니면, `victim->bk->fd`와 `victim`이 동일한지 확인한다. 동일하지 않다면, error("malloc(): smallbin double linked list corrupted")를 발생시킨다.

     5. `victim`의 next chunk(in memory)의 `prev_inuse` bit를 설정하여, 사용 중임을 표시한다.

     6. bin list에서 이 chunk를 제거한다.

     7. `av`(arena)에 따라서, 이 chunk에 적합한 arena bit를 설정한다. (main_arena 유무에 따라서 chunk size 필드에 NON_MAIN_ARENA bit 설정)

     8. `alloc_perturb`를 호출한 뒤, 이 포인터를 리턴한다.

   - size가 smallbin 범위가 아닐 때 (large bin에 속함):

     1. 요청된 size에 따라서 적절한 bin에 접근하기 위해 largebin array의 index를 가져온다. 주어진 크기에 맞는 large bin의 index를 계산하여 idx 지역변수에 저장한다.

     2. `av`가 fastchunks인지 아닌지 확인한다. 이 작업은 `av->flags`의 `FASTCHUNKS_BIT`를 체크하여 확인된다. fastchunks일 경우, `av`에 대해서 `malloc_consolidate`를 호출하여, 모든 fastbins을 병합시켜 큰 chunk로 만든다. 이는 큰 메모리 요청을 받은 경우에는 더 이상 작은 크기의 요청이 당분간 없을 것이라고 가정하기 때문임. 이로 인해 fastbin으로 인한 fragementation 문제를 줄일 수 있다.

   

4. 만약 여기까지 도달했다면(리턴된 포인터가 존재하지 않는다면), 이는 다음 중 하나 이상을 의미한다.

   1. size가 fastbin 범위이지만, 사용가능한 fastchunk가 존재하지 않는 경우

   2. size가 smallbin 범위이지만, 사용가능한 smallchunk가 존재하지 않는 경우(초기화 중 `malloc_consolidate`를 호출)

   3. size가 largebin 범위인 경우

      

5. 그런 다음, 다음 과정과 같이 unsotred chunks를 체크하고, 통과된 chunk를 bin에 넣는다. 이 지점이 chunk를 bins(smallbin, largebin)에 집어넣는 유일한 부분이다. 'TAIL'에서 unsorted bin을 반복한다. 요청을 처리할 chunk를 찾았으면 리스트에서 분리한다. 해당 과정을 단계적으로 살펴나가면 다음과 같다.

   1. unsorted bin list의 가장 TAIL chunk가 `victim` chunk로 선택된다. 다음의 전체 과정은 `victim != unsorted_chunks (av)`하는 동안, 즉 unsorted bin list가 모두 소모될 때까지 진행된다.

   2. `victim`의 chunk size가 최소 chunk size인 minimum(`2*SIZE_SZ`)과 시스템이 허용하는 최대 메모리 size인 maximum(`av->system_mem`) 사이에 존재하는지 확인한다. 그렇지 않으면, error("malloc(): memory corruption")을 발생시킨다.

   3. 만약 요청된 chunk의 size가 smallbin 범위이고, `victim`이 unsorted bin에 존재하는 유일한 chunk이고, last remainder chunk이며, `victim`의 chunk size가 (요청된 크기 + 최소 chunk size)보다 크거나 같은 경우

      1.  victim은 다음 두 chunk로 나뉘게 된다.

         - 요청된 size에 맞춰서 반환될 첫 번째 chunk(victim).
         - 사용자의 요청을 처리하고 남은 remainder chunk. 해당 chunk는 new last remainder chunk가 되며, unsorted bin에 추가된다. (이제 이 chunk가 unsorted bin list의 유일한 chunk가 됨)

      2. remainder chunk의 size가 large bin size라면, remainder chunk의 next_size를 모두 NULL로 채운다.

      3. 두 chunks의 `size`와 `prev_inuse` 필드가 적절하게 설정된다. remainder chunk의 물리적으로 next chunk의 prev_size 필드에는 remainder chunk size를 저장한다.

      4. `victim`에 `alloc_perturb`을 호출하여 초기화한 뒤, 반환한다. (종료)

         

   4. 만약 위 조건들(3.)을 만족하지 못한다면 이 항목에 도달하게 된다. unsorted bin list에서 `victim`을 제거한다. 만약 `victim`이 요청된 size와 정확하게 일치한다면, `alloc_perturb`를 호출하여 초기화 한 뒤, victim을 반환한다. (종료)

   5. victim의 size에 맞는 bin list에 삽입한다. victim의 size에 따라 다음과 같이 나뉘어 동작한다.

      - small bin size인 경우 : 그냥 집어넣는다.
        1. 해당 bin list의 제일 처음(HEAD)에 집어 넣는다.
      - large bin size인 경우 : 적절한 위치를 찾은 뒤, 집어 넣는다.
        - 해당 bin list에 기존 freed chunk가 존재하지 않는 경우 : 
          1. 해당 bin list에 victim을 추가한다.
        - 해당 bin list에 기존 freed chunk가 존재하는 경우 : 
          1. size에 prev_inuse bit를 설정한다. (비교 속도 향상을 위함. freed large chunk의 prev chunk는 분명 inuse bit가 설정되어 있는 chunk일 것임)
          2. 해당 bin list의 가장 TAIL의 chunk에 NON_MAIN_ARENA bit가 설정되어 있는지 확인한다. main_arena가 아니면 오류(assert)
          3. victim의 size가 해당 bin list 내에서 가장 작은 size를 갖는 chunk(TAIL)의 size보다 작은 경우, bin list에 victim을 추가한다. (nextsize list 포함)
          4. 그렇지 않다면, bk_nextsize로 건너뛰는 루프를 실행하여 `victim`의 size보다 작거나 같은 chunk size를 찾는다. 크기가 같으면 항상 두 번째 위치에 추가하고(해당 size의 첫 번째 chunk는 nextsize list를 구성하기 때문), 다르면 bin list 중간에 추가하고 nextsize list에도 추가한다. 

   6. 이 전체 과정을 `MAX_ITERS` (10000)의 maximum 번 반복하거나, 5.1.에서 언급했다시피 unsorted bin의 모든 chunk가 고갈될 때까지 반복한다.

      

6. unsorted bin chunk를 체크한 뒤에, 요청된 size가 small bin 범위가 아닌지 확인한다. 만약 small bin 범위가 아니라면, 이제 largebin을 사용한다.

   1. 요청된 size에 따라서 적절한 bin에 접근하기 위해 largebin array의 index를 가져온다.
   2. 만약 the largest chunk(bin에서 첫 번째 chunk. 내림차순이기 때문에 첫 번째 chunk가 가장 크다.)의 size가 요청된 size보다 클 경우:
      1. 요청된 size보다 크거나 같은 가장 작은 size를 가진 `victim` chunk를 찾기 위해 'TAIL'에서 부터 반복한다. victim을 victim->bk_nextsize로 설정한다. 이제 victim은 해당 bin 내의 가장 작은 크기의 chunk이다. victim의 크기가 주어진 크기보다 커질 때까지 victim을 victim->bk_nextsize로 변경하는 것을 반복.
      2. 요청을 처리할 chunk를 찾았으면, 해당 bin에서 `victim`을 제거하기 위해 `unlink`를 호출한다.
      3. `victim`의 chunk에 대해 `remainder_size`를 계산한다. (`victim` chunk size - requested size 임.)
      4. 만약 이 `remainder_size`가 `MINSIZE`보다 크거나 같다면(`remainder_size` >= `MINSIZE`, minimum chunk size는 헤더에 포함되어 있음.), 해당 chunk를 두 chunk로 나눈다.
         그렇지 않으면, 전체 `victim` chunk가 리턴된다. remainder chunk는 unsorted bin의 'HEAD'에 삽입된다. unsorted bin에서 `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)`를 검사한다. 그렇지 않으면 error("malloc(): corrupted unsorted chunks")를 발생시킨다.
      5. `alloc_perturb`를 호출하여 초기화 한 뒤, `victim` chunk를 반환한다.

      

7. 지금까지는, unsorted bin과 각 각의 fast, small, large bin들에 대해 검사를 진행했다. 요청된 chunk의 정확한 size를 이용하여 fast나 small bin같은 single bin을 검사하였다. 모든 bin을 사용할 때까지 다음 단계를 반복한다. 여기까지 왔다면 해당하는 bin 내에서 적당한 chunk를 찾지 못한 거다. idx 값을 하나 증가시킨 후 더 큰 크기의 bin 내에 free chunk가 있는지 확인한다. bitmap을 이용해 빨리 확인할 수 있다.

   1. next bin을 체크하기 위해, bin array의 index가 증가된다.

   2. empty한 bin들을 넘기기 위해 `av->binmap`을 사용한다. 현재 index에 해당하는 bitmap을 검사하여 free chunk가 있는지 확인한다. 만약 해당 bin이 empty하다면 index를 하나 증가시킨 후 검사를 다시한다. 모든 bitmap을 검사했다면 8번 과정(top chunk)으로 넘어간다.

   3. `victim`은 현재 bin의 'TAIL'을 가리킨다. bitmap이 설정된 bin이 있다면, 해당 bin 내의 가장 오래된(가장 작은 크기의) chunk를 victim 지역 변수에 저장한다.

   4. victim을 list에서 분리한다. unlink

   5. binmap을 사용하는 것은 bin을 스킵할 경우, 그것이 확실하게 empty한 상태인 것을 보장한다. 하지만, 모든 bin이 스킵된다는 것을 보장하지 못한다. `victim`이 empty한지 아닌지를 확인해야 한다. 만약 `victim`이 empty하다면, nonempty bin에 도착할 때까지 bin을 스킵하고, 위의 프로세스를 반복해야한다.(혹은 이 루프를 반복한다.) 

   6. victim의 크기가 요청을 처리하고도 다른 chunk를 구성할 수 있을 정도로 크다면, 분할하여 chunk를 두 개의 chunk로 나눈다.(`victim`은 nonempty chunk의 last chunk를 가리키는 상태) remainder chunk를 unsorted bin에 추가한다.(unsortd bin의 'TAIL'에) unsorted bin에서 `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)`인지를 확인한다. 그렇지 않으면 error("malloc(): corrupted unsorted chunks 2")를 발생시킨다. chunk의 크기가 small bin에 속한다면 last_remainder 변수가 remainder chunk를 가리키도록 설정한다.

   7. `alloc_perturb`를 호출하여 초기화 한 뒤, `victim` chunk를 반환한다.

      

8. 만약 어떤 empty한 bin도 발견하지 못 한다면, 요청을 처리하기 위해 top chunk가 사용된다.

   1. `victim`은 `av->top`을 가리킨다.
   2. 만약 top chunk의 size가 요청된 크기 + `MINSIZE` 라면(size of top chunk >= requested size + `MINSIZE`), top chunk를 두 chunk로 나눈다. 이 경우, the remainder chunk가 새로운 top chunk가 되고, 남은 chunk(victim)는 `alloc_perturb` 과정을 거친 후 사용자에게 리턴된다.
   3. 남은 arena 공간이 주어진 요청을 처리할 수 없을 경우에 주어진 요청의 크기가 small bin 영역에 속한다면 fastbin을 합병해서 할당을 시도한다. 먼저, `av`의 have_fastchunks 값을 확인한다.(fastbin chunk가 존재하는지 확인) 이 작업은 `av->flags`의 `FASTCHUNKS_BIT`를 확인하여 수행된다. 만약 fastchunks가 존재한다면, `av`에 대해 `malloc_consolidate`를 호출하여 fastbin chunks를 병합한다. 이 후, __libc_malloc()에서 재할당을 요청하면서 chunk가 할당된다.
   4. 만약 `av`가 fastchunks를 보유하지 못 했다면, 시스템의 heap 영역을 늘려야 하기 때문에 `sysmalloc`을 호출하고, `alloc_perturb`를 호출하여 해당 chunk를 초기화한 뒤, 얻은 포인터를 반환한다.



#### sysmalloc

1. 먼저 요청된 크기가 mmap() 시스템 콜을 이용하도록 설정된 범위에 속하고 (요청이 128KB보다 크거가 같을 경우), mmap() 사용 횟수 제한을 넘지 않는다면 ( < 65536회 ) mmap()을 호출한다. 호출이 성공하면 chunk에 M (IS_MMAPPED) 플래그를 설정하고 데이터 영역의 포인터를 반환한다. mmap()으로 할당한 chunk는 분할할 수 없으므로, 크기에 여유가 있더라도 하나의 chunk로 사용된다.
2. 그보다 작은 크기이거나 mmap() 호출이 실패했다면 heap 영역을 늘려야 한다. 증가시킬 크기는 요청한 크기에서 원래의 top chunk 크기를 빼고 top chunk가 기본적으로 가져야 할 여유 공간의 크기(pad)를 더한 후 할당 후 남은 영역에 chunk를 구성하기 위한 최소 크기를 더한 값이다. 또한 이는 시스템 페이지 크기에 맞춰 조정된다.
3. 위에서 계산한 크기에 대해서 sbrk() (MORCORE라는 이름을 사용한다.) syscall을 호출한다.
4. 호출이 성공했다면 __after_morecore_hook이 정의되어 있는지 검사하여 이를 호출한다.
5. 호출이 실패했다면 크기와 횟수 제한에 상관없이 mmap() syscall을 호출하여 메모리 할당을 시도한다. 이것이 성공하면 해당 arena는 더 이상 연속된 주소 공간에 속하지 않으므로, NONCONTIGUOUS_BIT를 설정한다. 실패했다면 errno 변수를 ENOMEM으로 설정하고 NULL을 반환한다. (종료)
6. 할당된 영역이 chunk 단위로 정렬되었는지 다시 확인하여 필요한 경우 sbrk()를 다시 호출한다.
7. 이전의 sbrk() 호출이 성공적으로 수행되었다면 top 영역의 크기를 그에 맞게 늘린다.
8. 그렇지 않다면 메모리 정렬이 맞지 않거나 mmap 호출을 통해 불연속적인 구간이 할당된 경우이다. 메모리 주소를 정렬하여 다시 한 번 sbrk()를 호출하고 불연속적인 구간의 끝부분에 dummy chunk를 2개 할당하여 원래의 top chunk가 불연속적인 공간과 consolidate되지 않도록 한다.
9. 이제 새로 할당된 영역을 분할하여 요청을 처리하고 나머지 영역을 새로운 top chunk로 설정한다.



이전 chunk와 다음 chunk를 구하는 작업은 chunk_at_offset 매크로를 이용하여 간단하게 처리한다.



calloc() 함수의 경우, malloc()과 동일하게 _int_malloc 함수를 호출하고 할당된 메모리를 모두 0으로 채운 뒤 리턴한다.

realloc() 함수의 경우, 먼저 현재 chunk에 요청을 처리할 만한 여유 공간이 있거나, 바로 다음 chunk가 free chunk이고 이 둘을 합친 크기가 요청을 처리할 수 있다면 둘을 병합하여 리턴한다. 그렇지 않으면 _int_malloc() 함수를 호출한 뒤 이전의 메모리 내용을 새로 할당된 chunk로 복사하고 이전 chunk를 free한 뒤 새로운 chunk를 리턴한다.





#### __libc_free (void * mem)

1. __free_hook이 설정되어 있다면 해당 hook을 호출하고 종료한다.
2. 주어진 mem 포인터로부터 chunk의 포인터를 얻는다.
3. `mem`이 NULL이라면 리턴한다.
4. 해당 chunk가 mmapped되면, 동적 brk/mmap 임계 값을 조정해야 하는 경우, `munmap_chunk`를 호출하여 메모리를 해제한다. (종료)
5. 그렇지 않은 경우, 해당 chunk의 arena 포인터를 가져오고, lock을 건다.
6. `_int_free`를 호출한다.
7. arena lock을 해제한다.





#### _int_free (mstate av, mchunkptr p, int have_lock)

1. chunk의 헤더 정보를 통해 해당 chunk의 크기를 얻는다.

2. `p`가 `p + chunksize(p)` 이전에 존재하는지 확인한다.(in memory, 덮어쓰기를 피하기 위해서) 그렇지 않으면 error("free(): invalid pointer")를 발생시킨다.

3. chunk가 최소 `MINSIZE`의 크기인지 또는 `MALLOC_ALIGNMENT`의 배수인지 확인한다. 그렇지 않으면 error("free(): invalid pointer")를 발생시킨다.

   

4. chunk의 size가 fastbin 범위이면 다음 작업을 수행한다.
   1. next chunk의 size가 minimum과 maximum size(`av->system_mem`) 범위 안에 존재하는지 확인한다. 그렇지 않으면 error("free(): invalid next size (fast)")를 발생시킨다.

   2. 해당 chunk에 대해 `free_perturb`를 호출한다.

   3. `av`에 `FASTCHUNKS_BIT`를 설정한다. 해당 arena가 fastbin chunk를 포함한다고 표시

   4. chunk size에 따라 fastbin array의 index를 가져온다.

   5. 해당 fastbin의 top에 존재하는 chunk와 우리가 추가하려는 chunk와 동일한지 확인한다. 동일하다면 중복해서 free를 호출한 경우이므로, error("double free or corruption (fasttop)")을 발생시킨다.

   6. 해당 fastbin의 top에 존재하는 chunk의 size와 우리가 추가하려는 chunk의 size가 동일한지 확인한다. 동일하지 않다면 error("invalid fastbin entry (free)")를 발생시킨다. 

   7. fastbin list의 top에 해당 chunk를 추가한 뒤(제일 앞에), 리턴한다.

      

5. 해당 chunk가 mmapped 된 chunk가 아니라면 다음 작업을 수행한다.
   1. 해당 chunk가 top chunk인지 아닌지를 확인한다. top chunk라면, error("double free or corruption (top)")을 발생시킨다.

   2. next chunk(by memory)가 해당 arena의 범위 안에 존재하는지 확인한다. 그렇지 않다면 error("double free or corruption (out)")을 발생시킨다.

   3. next chunk(by memory)의 pre_inuse bit가 설정되어있는지 아닌지 확인한다. 설정되어 있지 않다면, error("double free or corruption (!prev)")를 발생시킨다.

   4. next chunk의 size가 miminum과 maximum size (`av->system_mem`) 범위안에 존재하는지 확인한다. 그렇지 않다면, error("free(): invalid next size (normal)")을 발생시킨다.

   5. 해당 chunk에 대해서 `free_perturb`를 호출한다.

   6. previous chunk (by memory)가 사용 중이 아니라면, previous chunk에 대해 `unlink`를 호출한다.

   7. next chunk (by memory)가 top chunk가 아니라면, 다음 작업을 수행한다.
      1. next chunk (by memory)가 사용 중이 아니라면, next chunk에 대해 `unlink`를 호출한다.
      2. (free 되었을 경우) previous, next chunk (by memory)와 현재 chunk를 합병한 뒤, unsorted bin의 head에 추가한다. 추가 전, `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)`인지 확인한다. 그렇지 않다면, error("free(): corrupted unsorted chunks")를 발생시킨다.

   8. next chunks (by memory)가 top chunk라면, 해당 chunk를 하나의 top chunk로 병합시킨다.

   9. next chunk가 top chunk가 아니고 사용 중인 chunk라면, next chunk의 prev_inuse bit를 지운다.

      

6. 현재 chunk가 top chunk가 아니라면, unsorted bin에 추가하고 현재 chunk의 size 필드와 next chunk의 prev_size 필드에 현재 chunk의 size를 기록한다.

7. 병합된 현재 chunk의 size가 64K 이상이고 현재 arena가 fast bin을 포함하면 malloc_consolidate를 호출하여 fast bin 병합을 한다.

8. 현재 chunk의 size가 정해진 size(128K)이상이면 systrim() 함수를 호출하여 top chunk의 size를 줄이려고 시도한다. (systrim 함수는 top chunk가 sbrk를 통해 확장된 heap 영역에 속할 경우에만 수행되며 현재 top chunk의 크기에서 chunk 정보를 저장하기 위한 최소 크기와 top chunk가 기본적으로 가져야 할 여유 공간의 크기만큼을 뺀 크기를 페이지 단위로 조정하여 sbrk를 호출한다. 또한 __after_morecore_hook이 정의되어 있다면 해당 hook을 호출한 뒤 top chunk의 크기를 조정한다.)

9. 해당 chunk가 mmapped라면 `munmap_chunk`를 호출한다.









## Security Checks

다음은 heap과 관련된 공격을 감지 및 막기 위해서 glibc에서 시행하는 보안 기법들을 요약한 것이다.

| Function    | Security Check                                               | Error                                           |
| ----------- | ------------------------------------------------------------ | ----------------------------------------------- |
| unlink      | Whether chunk size is equal to the previous size set in the next chunk (in memory) | corrupted size vs. prev_size                    |
| unlink      | Whether `P->fd->bk == P` and `P->bk->fd == P`*               | corrupted double-linked list                    |
| _int_malloc | While removing the first chunk from fastbin (to service a malloc  request), check whether the size of the chunk falls in fast chunk size  range | malloc(): memory corruption (fast)              |
| _int_malloc | While removing the last chunk (`victim`) from a smallbin (to service a malloc request), check whether `victim->bk->fd` and `victim` are equal | malloc(): smallbin double linked list corrupted |
| _int_malloc | While iterating in unsorted bin, check whether size of current chunk is within minimum (`2*SIZE_SZ`) and maximum (`av->system_mem`) range | malloc(): memory corruption                     |
| _int_malloc | While inserting last remainder chunk into unsorted bin (after splitting a large chunk), check whether `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)` | malloc(): corrupted unsorted chunks             |
| _int_malloc | While inserting last remainder chunk into unsorted bin (after splitting a fast or a small chunk), check whether `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)` | malloc(): corrupted unsorted chunks 2           |
| _int_free   | Check whether `p`** is before `p + chunksize(p)` in the memory (to avoid wrapping) | free(): invalid pointer                         |
| _int_free   | Check whether the chunk is at least of size `MINSIZE` or a multiple of `MALLOC_ALIGNMENT` | free(): invalid size                            |
| _int_free   | For a chunk with size in fastbin range, check if next chunk's size is between minimum and maximum size (`av->system_mem`) | free(): invalid next size (fast)                |
| _int_free   | While inserting fast chunk into fastbin (at `HEAD`), check whether the chunk already at `HEAD` is not the same | double free or corruption (fasttop)             |
| _int_free   | While inserting fast chunk into fastbin (at `HEAD`), check whether size of the chunk at `HEAD` is same as the chunk to be inserted | invalid fastbin entry (free)                    |
| _int_free   | If the chunk is not within the size range of fastbin and neither it  is a mmapped chunks, check whether it is not the same as the top chunk | double free or corruption (top)                 |
| _int_free   | Check whether next chunk (by memory) is within the boundaries of the arena | double free or corruption (out)                 |
| _int_free   | Check whether next chunk's (by memory) previous in use bit is marked | double free or corruption (!prev)               |
| _int_free   | Check whether size of next chunk is within the minimum and maximum size (`av->system_mem`) | free(): invalid next size (normal)              |
| _int_free   | While inserting the coalesced chunk into unsorted bin, check whether `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)` | free(): corrupted unsorted chunks               |



malloc의 보조 함수들 : http://studyfoss.egloos.com/5209389

malloc 동작 : 
https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks.html1
http://studyfoss.egloos.com/5206979
https://umbum.tistory.com/386?category=761562
https://say2.tistory.com/entry/glibc-mallocc%EC%9D%98-malloc%ED%95%A8%EC%88%98-%EB%B6%84%EC%84%9D-%EC%95%BD%EA%B0%84%EC%9D%98-exploit%EA%B4%80%EC%A0%90?category=669964
https://tribal1012.tistory.com/141

https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf





SIZE_SZ는 INTERNAL_SIZE_T를 거쳐 최종적으로는 size_t의 크기와 같다. 따라서 64bit의 경우 8 bytes이고 32bit의 경우 4 bytes이다.



```c
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
    fastbin은 single-link list라서 중간에서 제거될 수 없음. 또한, 다른 bins과 다르게 LIFO(Last In First Out) 순으로 동작한다.
 */
typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)
#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)
```



```c
get_max_fast
static inline INTERNAL_SIZE_T
get_max_fast (void)
{
  /* Tell the GCC optimizers that global_max_fast is never larger
     than MAX_FAST_SIZE.  This avoids out-of-bounds array accesses in
     _int_malloc after constant propagation of the size parameter.
     (The code never executes because malloc preserves the
     global_max_fast invariant, but the optimizers may not recognize
     this.)  
     
  */
  if (global_max_fast > MAX_FAST_SIZE)
    __builtin_unreachable ();
  return global_max_fast;
}

fastbin_index
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
  
typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)
#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)
  
fastbin
fastbin_pop_entry
chunksize
check_remalloced_chunk

csize2tidx
```







```c
/*
   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
   that triggers automatic consolidation of possibly-surrounding
   fastbin chunks. This is a heuristic, so the exact value should not
   matter too much. It is defined at half the default trim threshold as a
   compromise heuristic to only attempt consolidation if it is likely
   to lead to trimming. However, it is not dynamically tunable, since
   consolidation reduces fragmentation surrounding large chunks even
   if trimming is not used.
   이 값이상의 size를 가진 chunk에 대해 free를 호출했을 경우, 자동으로 fastbin chunk들을 consolidate 함.
 */
#define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)

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
```











