#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

#define ALIGNOF(type) offsetof (struct { char c; type member; }, member)
#define NORETURN __attribute__((noreturn))

#define NUMELTS(arr) ( sizeof((arr)) / sizeof((arr)[0]) )

enum FORTH_ERROR_CODE {
  FORTH_OKAY = 0,

  FORTH_ERROR_DATA_UNDERFLOW = 1,
  FORTH_ERROR_DATA_OVERFLOW     ,
  FORTH_ERROR_HEAP_EXHAUSTED    ,

  FORTH_ERROR_CONTROL_UNDERFLOW ,
  FORTH_ERROR_CONTROL_OVERFLOW  ,

  FORTH_ERROR_INVALID_TYPE      ,
  FORTH_ERROR_INVALID_OPCODE    ,

  FORTH_ERROR_UNIMPLEMENTED     ,
};

enum FORTH_TYPE {
  FORTH_BYTE    = 1,
  FORTH_INT32      ,
  FORTH_FLOAT32    ,
  FORTH_STRING     ,
  FORTH_CODE       ,
  FORTH_CCODE      ,
  FORTH_ADDRESS
};

union forth_value_data {
  int32_t val;
  float fp;
};

struct forth_value {
  int32_t type;
  union forth_value_data data;
};

typedef void (*forth_cfunc)(void);

enum FORTH_VM_CODES {
  FORTH_VM_NOP       =  0,
  FORTH_VM_DROP      =  1,
  FORTH_VM_DUP       =  2,
  FORTH_VM_COPY      =  3,
  FORTH_VM_SWAP      =  4,
  FORTH_VM_PUSHINT   =  5,
  FORTH_VM_PUSHFLT   =  6,
  FORTH_VM_PUSHADDR  =  7,
  FORTH_VM_FETCH     =  8,
  FORTH_VM_STORE     =  9,
  FORTH_VM_CALL      = 10,
  FORTH_VM_CALLC     = 11,
  FORTH_VM_UJMP      = 12,
  FORTH_VM_CJMP      = 13,
  FORTH_VM_PUSHDICT  = 14,
  FORTH_VM_POPDICT   = 15,
  FORTH_VM_RETURN    = 16,
  FORTH_VM_INTOP     = 17,
  FORTH_VM_NEGATE    = 18,
  FORTH_VM_TOP       = 19,
  FORTH_VM_INCR      = 20,
  FORTH_VM_DECR      = 21,
  FORTH_VM_DO        = 22,
  FORTH_VM_LOOP      = 23,
  FORTH_VM_LOOPIDX   = 24,
  FORTH_VM_EMIT      = 25,
};

enum {
  FORTH_FLAG_COMPILER_WORD = 0x01,
};

#define FORTH_CELL_MEM         65536 /* 64K */
#define FORTH_HEAP_MEM      16777216 /* 16M */
#define FORTH_STRPOOL_MEM      65536 /* 64K for strings */
#define FORTH_DICTPOOL_SIZE    65536 /* 64K dict entries */

#define FORTH_NUM_CELLS  (FORTH_CELL_MEM / sizeof(struct forth_value)) /* 64K / sizeof(forth_value) */
#define FORTH_HEAP_SIZE  (FORTH_HEAP_MEM / sizeof(int32_t))            /* 16M / sizeof(int32_t) */

#define FORTH_EMIT_SIZE 512

#define FORTH_STRPOOL_SIZE  (FORTH_STRPOOL_MEM / sizeof(char))          /* 64K for strings */

// static struct forth_value forth_cells[FORTH_CELLS];
static int32_t forth_heap[FORTH_HEAP_SIZE];
static int32_t emit_ptr = FORTH_HEAP_SIZE - FORTH_EMIT_SIZE;

static int32_t emit_stack[16];
static int32_t emit_stack_top = 0;
#define emit_top (emit_stack[emit_stack_top-1])

static unsigned char strpool[FORTH_STRPOOL_SIZE];

struct forth_dict_entry {
  int32_t name;
  int32_t flags;
  // int32_t next;
  int32_t data;
};

static struct forth_dict_entry dictpool[FORTH_DICTPOOL_SIZE];

struct forth_dict {
  int32_t parent;
  // int32_t head;

  // int32_t cell_base;
  int32_t heap_base;
  int32_t heap_top;

  int32_t strpool_base;
  int32_t strpool_top;

  int32_t base;
  int32_t top;
};

struct forth_dict the_dict;

#define FORTH_ISTACK_SIZE 1024
#define FORTH_DSTACK_SIZE 1024
#define FORTH_CSTACK_SIZE  128

static int32_t call_stack[FORTH_ISTACK_SIZE];
static int32_t call_top = 0;

static int32_t control_stack[FORTH_CSTACK_SIZE];
static int32_t control_top = 0;

static struct forth_value data_stack[FORTH_DSTACK_SIZE];
static int32_t data_top = 0;

static jmp_buf* error_handler = NULL;


#define FORTH_INPUT_SIZE 256
/*
static char forth_input_buffer[FORTH_INPUT_SIZE];
static int forth_input_base = 0;
*/

static struct forth_dict* curr_dict = NULL;

static inline void* heap_at(int32_t addr)
{
  return (void*)(forth_heap+addr);
}

/*
static struct forth_dict* top_dict(void)
{
  return (struct forth_dict*)heap_at(0);
}
*/

static void forth_add_builtins(struct forth_dict* dict);

static NORETURN void forth_error(enum FORTH_ERROR_CODE code)
{
  if (error_handler != NULL) {
    longjmp(error_handler[0], (int)code);
  } else {
    fprintf(stderr, "ERROR code 0x%04x with no handler\n", code);
    exit(EXIT_FAILURE);
  }
}

void forth_init(void)
{
  // memset(forth_cells+0,0,sizeof(cells));
  memset(forth_heap+0, 0,sizeof(forth_heap));

  call_top = 0;
  data_top = 0;

  // struct forth_dict* dict = top_dict();
  the_dict.parent    = -1;
  // the_dict.head      = -1;
  // dict->cell_base = 0;
  the_dict.heap_base = 0;
  the_dict.heap_top  = 0;

  the_dict.strpool_base = 0;
  the_dict.strpool_top  = 0;

  the_dict.base = 0;
  the_dict.top  = 0;

  curr_dict = &the_dict;

  forth_add_builtins(&the_dict);
}

union forth_instruction {
  unsigned char bytes[4];
  int16_t half[2];
  int32_t whole;
};

static void forth_ccall(int32_t addr)
{
  forth_cfunc fp = NULL;
  memcpy(&fp, heap_at(addr), sizeof(fp));
  fp();
}

static inline void pushcall(int32_t ip)
{
  /* FIXME: add optional range checking */
  call_stack[call_top] = ip;
  call_top++;
}

static inline int32_t popcall(void)
{
  if (call_top > 0) {
    call_top--;
    return call_stack[call_top];
  } else {
    return -1;
  }
}

static inline void pushdata(struct forth_value val)
{
  /* FIXME: add optional range checking */
  data_stack[data_top] = val;
  data_top++;
}

static inline void pushint(int32_t val)
{
  data_stack[data_top].type = FORTH_INT32;
  data_stack[data_top].data.val = val;
  data_top++;
}

static inline void pushfloat(float fp)
{
  data_stack[data_top].type = FORTH_FLOAT32;
  data_stack[data_top].data.fp = fp;
  data_top++;
}

static inline void pushaddr(int32_t addr)
{
  data_stack[data_top].type = FORTH_ADDRESS;
  data_stack[data_top].data.val = addr;
  data_top++;
}

static inline struct forth_value popdata(void)
{
  if (data_top > 0) {
    data_top--;
    return data_stack[data_top];
  } else {
    /* FIXME: set error condition */
    forth_error(FORTH_ERROR_DATA_UNDERFLOW);
  }
}

static inline int32_t popint(void)
{
  if (data_top > 0 && data_stack[data_top-1].type == FORTH_INT32) {
    data_top--;
    return data_stack[data_top].data.val;
  } else if (data_top > 0) {
    forth_error(FORTH_ERROR_INVALID_TYPE);
  } else {
    forth_error(FORTH_ERROR_DATA_UNDERFLOW);
  }
}

static inline int incr_ctl(void)
{
  if (control_top > 2) {
    control_stack[control_top-2]++;
    if (control_stack[control_top-2] < control_stack[control_top-1]) {
      return control_stack[control_top-3];
    }
  }
  return -1;
}

static inline void push_ctl(int32_t ip, int32_t i0, int32_t i1)
{
  if ((uint32_t)(control_top + 2) >= NUMELTS(control_stack)) {
    forth_error(FORTH_ERROR_CONTROL_OVERFLOW);
  }

  control_stack[control_top++] = ip;
  control_stack[control_top++] = i0;
  control_stack[control_top++] = i1;
}

static inline int32_t pop_ctl(void)
{
  if (control_top > 2) {
    control_top -= 3;
    return control_stack[control_top];
  }
  forth_error(FORTH_ERROR_CONTROL_UNDERFLOW);
}

static inline struct forth_value peekdata(void)
{
  if (data_top > 0) {
    return data_stack[data_top-1];
  } else {
    /* FIXME: set error condition */
    forth_error(FORTH_ERROR_DATA_UNDERFLOW);
  }
}

union pair32 {
  int64_t i64;
  int32_t i32[2];
};

static inline union pair32 decode_int_arg(union forth_instruction fetch, int32_t ip)
{
  union pair32 ret;
  int32_t v;

  if (fetch.bytes[1] & 0x80) { /* ENCODED flag */
    v = fetch.half[1] + ((fetch.bytes[1] & 0x3f) << 16);
  } else {
    ip++;
    v = forth_heap[ip];
  }

  ret.i32[0] = v;
  ret.i32[1] = ip;
  return ret;
}

static inline union pair32 decode_addr(register union forth_instruction fetch, register int32_t ip)
{
  int32_t addr;
  union pair32 ret;

  if (fetch.bytes[1] & 0x80) {
    int32_t delta = fetch.half[1] + ((fetch.bytes[1] & ~(0xC0)) << 16);
    if (fetch.bytes[1] & 0x40) {
      delta = -delta;
    }
    addr = ip+delta;
  } else {
    ip++;
    addr = forth_heap[ip];
  }

  ret.i32[0] = addr;
  ret.i32[1] = ip;
  return ret;
}

static inline void forth_intop(union forth_instruction fetch)
{
  int32_t b = popint();
  int32_t a = popint();

  switch (fetch.bytes[1]) {
    case '+':
      pushint(a+b);
      break;

    case '-':
      pushint(a-b);
      break;

    case '*':
      pushint(a*b);
      break;

    case '/':
      pushint(a/b);
      break;

    case '&':
      pushint(a&b);
      break;

    case '|':
      pushint(a|b);
      break;

    case '^':
      pushint(a^b);
      break;

    case '<':
      pushint(a<b);
      break;

    case '>':
      pushint(a>b);
      break;

    case '=':
      pushint(a==b);
      break;

    case '{':
      pushint(a<=b);
      break;

    case '}':
      pushint(a>=b);
      break;

    default:
      forth_error(FORTH_ERROR_INVALID_OPCODE);
  }
}

#define GET_ADDR_ARG(_var,_ip) do { \
  union pair32 arg = decode_addr(fetch,ip); \
  _var = arg.i32[0]; ip = arg.i32[1]; \
} while(0)

int forth_vm(int32_t ip)
{
  union forth_instruction fetch;
  int ret = 0;

  jmp_buf* prev_handler = error_handler;
  jmp_buf this_handler;

  int code = setjmp(this_handler);
  if (code == 0) {
    error_handler = &this_handler;
  } else {
    fprintf(stderr, "ERROR code 0x%04x caught by handler\n", code);
    ret = code;
    goto cleanup;
  }

  for(;;) {
do_fetch:
    fetch.whole = forth_heap[ip];

    switch ((enum FORTH_VM_CODES)fetch.bytes[0]) {
      case FORTH_VM_NOP:
        break;

      case FORTH_VM_DROP:
        if (data_top > 0) { data_top--; }
        break;

      case FORTH_VM_DUP:
        if (data_top > 0) {
          data_stack[data_top] = data_stack[data_top-1];
          data_top++;
        }
        break;

      case FORTH_VM_SWAP:
        if (data_top > 1) {
          struct forth_value tmp = data_stack[data_top-2];
          data_stack[data_top-2] = data_stack[data_top-1];
          data_stack[data_top-1] = tmp;
        }
        break;

      case FORTH_VM_COPY:
        {
          int32_t ind;
          if (fetch.bytes[1] == 1) {
            ind = fetch.half[1];
          } else {
            ind = popint();
          }
          if (ind < 0) {
            ind = data_top-ind-1;
          }

          if (ind > 0 && ind <= data_top) {
            pushdata( data_stack[ind-1] );
          } else {
            forth_error(FORTH_ERROR_DATA_UNDERFLOW);
          }
        }
        break;

      case FORTH_VM_PUSHINT:
        do {
          union pair32 arg = decode_int_arg(fetch, ip);
          pushint(arg.i32[0]);
          ip = arg.i32[1];
        } while(0);
        break;

      case FORTH_VM_PUSHFLT:
        ip++;
        pushint(forth_heap[++ip]);
        break;

      case FORTH_VM_PUSHADDR:
        do {
          union pair32 arg = decode_int_arg(fetch, ip);
          pushaddr(arg.i32[0]);
          ip = arg.i32[1];
        } while(0);
        break;

      case FORTH_VM_FETCH:
        if (data_top > 0 && data_stack[data_top-1].type == FORTH_ADDRESS) {
          int32_t addr = data_stack[data_top-1].data.val;
          data_stack[data_top-1].type = forth_heap[addr+0];
          data_stack[data_top-1].data.val  = forth_heap[addr+1];
        } else {
          /* set error state */
          if (data_top > 0) {
            forth_error(FORTH_ERROR_INVALID_TYPE);
          } else {
            forth_error(FORTH_ERROR_DATA_UNDERFLOW);
          }
        }
        break;

      case FORTH_VM_STORE:
        if (data_top > 1 && data_stack[data_top-2].type == FORTH_ADDRESS) {
          int32_t addr = data_stack[data_top-2].data.val;
          forth_heap[addr+0] = data_stack[data_top-1].type;
          forth_heap[addr+1] = data_stack[data_top-1].data.val;
          data_top--;
        }
        break;

      case FORTH_VM_CALL:
        {
          int32_t new_ip;
          GET_ADDR_ARG(new_ip,ip);
          if (new_ip == ip) {
            struct forth_value arg = peekdata();
            if (arg.type != FORTH_ADDRESS) {
              forth_error(FORTH_ERROR_INVALID_TYPE);
            }
            popdata();
            new_ip = arg.data.val;
          }

          pushcall(ip);
          ip = new_ip;
          goto do_fetch;
        }

      case FORTH_VM_CALLC:
        {
          int32_t addr;
          GET_ADDR_ARG(addr,ip);

          pushcall(ip);
          forth_ccall(addr);
          ip = popcall();
        }
        break;

      case FORTH_VM_UJMP:
        {
          int32_t addr;
          GET_ADDR_ARG(addr,ip);
          ip = addr;
          goto do_fetch;
        }

      case FORTH_VM_CJMP:
        if (popint()) {
          int32_t addr;
          GET_ADDR_ARG(addr,ip);
          ip = addr;
          goto do_fetch;
        }

      case FORTH_VM_RETURN:
        {
          int32_t ret = popcall();
          if (ret >= 0) {
            ip = ret;
          } else {
            goto cleanup;
          }
        }
        break;

      case FORTH_VM_DO:
        {
          int32_t i0 = popint();
          int32_t i1 = popint();
          push_ctl(ip,i0,i1);
        }
        break;

      case FORTH_VM_LOOP:
        {
          int32_t addr = incr_ctl();
          if (addr >= 0) {
            ip = addr;
          }
          pop_ctl();
        }
        break;

      case FORTH_VM_LOOPIDX:
        {
          int32_t cind = control_top - 3*(fetch.bytes[1]+1);
          if (cind > 0) {
            pushint(control_stack[cind+1]);
          } else {
            forth_error(FORTH_ERROR_CONTROL_UNDERFLOW);
          }
        }
        break;

      case FORTH_VM_EMIT:
        {
          int32_t val = popint();
          fputc((int)val, stdout);
        }
        break;

      case FORTH_VM_INCR:
        if (data_top > 0) {
          data_stack[data_top].data.val++;
        }
        break;

      case FORTH_VM_DECR:
        if (data_top > 0) {
          data_stack[data_top].data.val--;
        }
        break;

      case FORTH_VM_PUSHDICT:
      case FORTH_VM_POPDICT:
      // default:
        forth_error(FORTH_ERROR_UNIMPLEMENTED);

      case FORTH_VM_INTOP:
        forth_intop(fetch);
        break;

      case FORTH_VM_NEGATE:
        {
          int32_t a = popint();
          pushint(-a);
        }
        break;

      case FORTH_VM_TOP:
        {
          pushint(data_top);
        }
        break;
    }

    ip++;
  }

cleanup:
  error_handler = prev_handler;
  return ret;
}

// static struct  new_dict(

static int enough_heap(size_t nwords)
{
  int32_t new_top = curr_dict->heap_top + nwords;
  return new_top < emit_ptr;
}

static int32_t heap_top(struct forth_dict* dict)
{
  return dict->heap_top;
}

static void heap_mark(struct forth_dict* dict, int32_t newtop)
{
  dict->heap_top = newtop;
}

static int32_t addstring(char* s, uint8_t len)
{
  uint32_t name_off = curr_dict->strpool_top;
  if (name_off + len + 2 > sizeof(strpool)) {
    return -1;
  }

  strpool[ name_off ] = len;
  memcpy(strpool+name_off+1, s, len);
  strpool[ name_off+len+1 ] = '\0';

  curr_dict->strpool_top += len+2;

  return name_off;
}

static int32_t dict_lookup1(struct forth_dict* dict, char* name, size_t n)
{
  if (n > 32) { n = 32; }
  register int32_t ind = dict->top;
  while (ind > 0) {
    ind--;
    register int32_t nptr = dictpool[ind].name;
    if (strpool[nptr] == n) {
      if (memcmp(name,strpool+nptr+1,n) == 0) {
        return ind;
      }
    }
  }

  return -1;
}

static inline int32_t dict_lookup(struct forth_dict* dict, char* name)
{
  return dict_lookup1(dict,name,strlen(name));
}

static int dict_add(struct forth_dict* dict, char* name, int32_t flags, int32_t data)
{
  register int32_t prev_entry;
  register int32_t name_off;
  register int32_t top;
  size_t n;

  top = dict->top;
  if (dict->top >= (int)NUMELTS(dictpool)) {
    return -1;
  }

  n = strlen(name);
  if (n > 32) { n = 32; }

  prev_entry = dict_lookup(dict,name);
  if (prev_entry < 0) {
    name_off = addstring(name,(uint8_t)n);
  } else {
    name_off = dictpool[prev_entry].name;
  }

  if (name_off < 0) {
    return -1;
  }

  dictpool[top].name  = name_off;
  dictpool[top].flags = flags;
  dictpool[top].data  = data;
  dict->top++;

  return 0;
}

static char* buf_beg = NULL;
static char* buf_end = NULL;
static char* buf_ptr = NULL;
static char* buf_nxt = NULL;
#define forth_state ((emit_stack_top > 0))
// static int32_t forth_state = 0;

static char wordname[32];

static void get_state(void)
{
  pushint(forth_state);
}

static void define_word(void);
static void define_noname(void);
static void finish_word(void);

static int32_t forth_token(void);

#define EMIT(mnemonic, arg1,arg2) do {    \
  union forth_instruction inst;           \
  inst.bytes[0] = FORTH_VM_ ## mnemonic;  \
  inst.bytes[1] = arg1;                   \
  inst.half[1] = arg2;                    \
  forth_heap[hp] = inst.whole;            \
  hp++;                                   \
} while(0)

#define ADD_CCALL(word, flags, func) do { \
  forth_cfunc fp = (func);                \
  dict_add(dict, word, flags, hp);        \
  EMIT(CALLC,0x80,2);                     \
  EMIT(RETURN,0,0);                       \
  memcpy(forth_heap+hp,&fp,sizeof(fp));   \
  hp += (sizeof(fp) / sizeof(forth_heap[0])); \
} while(0);

#define WORD(name) dict_add(dict, #name, 0, hp)

static void forth_add_builtins(struct forth_dict* dict)
{
  int32_t hp = heap_top(dict);

  WORD(NOP);
  EMIT(NOP,0,0);
  EMIT(RETURN,0,0);

  WORD(DROP);
  EMIT(DROP,0,0);
  EMIT(RETURN,0,0);

  WORD(DUP);
  EMIT(DUP,0,0);
  EMIT(RETURN,0,0);

  WORD(SWAP);
  EMIT(SWAP,0,0);
  EMIT(RETURN,0,0);

  WORD(INCR);
  EMIT(INCR,0,0);
  EMIT(RETURN,0,0);

  WORD(DECR);
  EMIT(DECR,0,0);
  EMIT(RETURN,0,0);

  WORD(TOP);
  EMIT(TOP,0,0);
  EMIT(RETURN,0,0);

  WORD(EXECUTE);
  EMIT(CALL,0x80,0);
  EMIT(RETURN,0,0);

  ADD_CCALL("STATE", 0, get_state);

  dict_add(dict, "<", 0, hp);
  EMIT(INTOP,'<',0);
  EMIT(RETURN,0,0);

  dict_add(dict, ">", 0, hp);
  EMIT(INTOP,'>',0);
  EMIT(RETURN,0,0);

  dict_add(dict, "=", 0, hp);
  EMIT(INTOP,'=',0);
  EMIT(RETURN,0,0);

  dict_add(dict, "+", 0, hp);
  EMIT(INTOP,'+',0);
  EMIT(RETURN,0,0);

  dict_add(dict, "-", 0, hp);
  EMIT(INTOP,'-',0);
  EMIT(RETURN,0,0);

  dict_add(dict, "*", 0, hp);
  EMIT(INTOP,'*',0);
  EMIT(RETURN,0,0);

  dict_add(dict, "/", 0, hp);
  EMIT(INTOP,'/',0);
  EMIT(RETURN,0,0);

  dict_add(dict, "&", 0, hp);
  EMIT(INTOP,'&',0);
  EMIT(RETURN,0,0);

  dict_add(dict, "|", 0, hp);
  EMIT(INTOP,'|',0);
  EMIT(RETURN,0,0);

  ADD_CCALL(":", FORTH_FLAG_COMPILER_WORD, define_word);
  ADD_CCALL(";", FORTH_FLAG_COMPILER_WORD, finish_word);
  ADD_CCALL(":NONAME", FORTH_FLAG_COMPILER_WORD, define_noname);
  // ADD_CCALL("':, 0, address

  heap_mark(dict, hp);
  // dict_add("CHAR", hp);
}
#undef EMIT
#undef WORD

static int32_t forth_token(void)
{
  buf_ptr = buf_nxt;
  while ((buf_ptr < buf_end) && isspace(*buf_ptr)) {
    buf_ptr++;
  }

  if (buf_ptr == buf_end) {
    return EOF;
  }

  buf_nxt = buf_ptr;
  while ((buf_nxt < buf_end) && !isspace(*buf_nxt)) {
    buf_nxt++;
  }

  return buf_nxt-buf_ptr;
}

static void print_stack(void)
{
  for(size_t i=data_top; i > 0; i--) {
    switch (data_stack[i-1].type) {
      case FORTH_INT32:
        fprintf(stdout, "[%3d] %10d\n", (int)(data_top-i+1), data_stack[i-1].data.val);
        break;
      case FORTH_FLOAT32:
        fprintf(stdout, "[%3d] %10.5f\n", (int)(data_top-i+1), (double)(data_stack[i-1].data.fp));
        break;
      case FORTH_ADDRESS:
        fprintf(stdout, "[%3d] PTR 0x%x\n", (int)(data_top-i+1), data_stack[i-1].data.val);
        break;
      default:
        fprintf(stdout, "[%3d] UNK 0x%x\n", (int)(data_top-i+1), data_stack[i-1].data.val);
        break;
    }
  }
}

static int emit_word(int32_t word)
{
  if (emit_top < (int)NUMELTS(forth_heap)) {
    forth_heap[emit_top] = word;
    emit_top++;
    return 0;
  } else {
    return -1;
  }
}

#define EMIT(word) do { \
  if (emit_word( (word) ) < 0) { \
    return -1;                   \
  } } while(0)

static int forth_compile(int32_t ip)
{
  union forth_instruction next_instr;
  next_instr.whole = forth_heap[ip+1];
  if (next_instr.bytes[0] == FORTH_VM_RETURN) {
    EMIT(forth_heap[ip]);
  } else {
    union forth_instruction inst;
    inst.whole = 0;
    inst.bytes[0] = FORTH_VM_CALL;
    EMIT(inst.whole);
    EMIT(ip);
  }

  return 0;
}

static int start_compiling(void);

#if 0
static void forth_if(void)
{
  if (forth_state)
  if (start_compiling() < 0) {
    /* set error! */
    fprintf(stderr, "cannot compile IF statement!\n");
    return;
  }
}

static void forth_then(void)
{
}
#endif /* 0 */

static int forth_literal(char* s, int32_t sz)
{
  char buf[32];
  union forth_instruction instr;
  union forth_value_data arg;

  if (sz+1 > (int)sizeof(buf)) {
    return 0;
  }

  memset(buf+0,0,sizeof(buf));
  memcpy(buf+0,s,sz);

  char* endp = NULL;
  long n = strtol(buf+0,&endp,0);
  if ((endp == NULL) || (*endp == '\0')) {
    if (forth_state == 0) {
      pushint((int32_t)n);
    } else {
      instr.whole = 0;

      if ((n > 0) && (n < 0x400000)) {
        instr.bytes[0] = FORTH_VM_PUSHINT;
        instr.half[1] = n & 0xffff;
        instr.bytes[1] = (n & 0x3f0000) >> 16 | 0x80;
        EMIT(instr.whole);
      } else if ((n < 0) && (-n < 0x400000)) {
        instr.bytes[0] = FORTH_VM_PUSHINT;
        instr.half[1] = n & 0xffff;
        instr.bytes[1] = (n & 0x3f0000) >> 16 | 0x80 | 0x40;
        EMIT(instr.whole);
      } else {
        instr.whole = 0;
        instr.bytes[0] = FORTH_VM_PUSHINT;
        EMIT(instr.whole);
        EMIT((int32_t)n);
      }
    }
    return 0;
  }

  float f = strtof(buf+0,&endp);
  if ((endp == NULL) || (*endp == '\0')) {
    if (forth_state == 0) {
      pushfloat(f);
    } else {
      instr.whole = 0;
      instr.bytes[0] = FORTH_VM_PUSHFLT;
      EMIT(instr.whole);
      arg.fp = f;
      EMIT(arg.val);
    }

    return 0;
  }

  return -1;
}

static int parse_token(int32_t toksz)
{
  int32_t dword = dict_lookup1(curr_dict, buf_ptr, toksz);
  if (dword < 0) {
    if (forth_literal(buf_ptr,toksz) < 0) {
      fprintf(stderr, "word not found: ");
      fwrite(buf_ptr, toksz, 1, stderr);
      fputc('\n', stderr);
      return -1;
    }

    return 0;
  }

  int32_t ip = dictpool[dword].data;
  if (forth_state == 0 || (dictpool[dword].flags & FORTH_FLAG_COMPILER_WORD) ) {
    int ret = forth_vm(ip);
    if (ret < 0) {
      return ret;
    }

    return 0;
  } else {
    return forth_compile(ip);
  }
}

static void print_status(void)
{
  print_stack();
  fprintf(stdout, "Heap: %d elements / %d\n",
      curr_dict->heap_top, emit_ptr);
}

int forth_parse(char* buf, size_t n)
{
  buf_beg = buf;
  buf_end = buf + n;

  buf_ptr = buf_nxt = buf_beg;

  int32_t toksz = forth_token();
  while (toksz > 0) {
    int ret = parse_token(toksz);
    if (ret < 0) {
      /* abort compilation */
      emit_stack_top = 0;
    }

    toksz = forth_token();
  }

  print_status();

  buf_ptr = buf_beg = buf_end = NULL;
  return 0;
}

static int start_compiling(void)
{
  if (emit_stack_top >= (int)NUMELTS(emit_stack)) {
    /* set error! */
    fprintf(stderr, "emit stack is full!\n");
    return -1;
  }

  register int32_t emit_base;
  if (emit_stack_top == 0) {
    emit_base = emit_ptr;
  } else {
    emit_base = emit_stack[emit_stack_top-1];
  }
  emit_stack[emit_stack_top] = emit_base;
  emit_stack_top++;

  memset(forth_heap+emit_base, 0, (NUMELTS(forth_heap) - emit_base)*sizeof(forth_heap[0]));

  if (emit_stack_top == 1) {
    memset(wordname+0,0,sizeof(wordname));
  }

  return 0;
}

static void define_word(void)
{
  if (forth_state) {
    /* set error! */
    fprintf(stderr, "cannot define word when already COMPILING\n");
    return;
  }

  int32_t toksz = forth_token();
  if (toksz == EOF) {
    /* set error! */
    fprintf(stderr, "unfinished definition!\n");
    return;
  }

  if (start_compiling() < 0) {
    return;
  }

  if (toksz > (int)sizeof(wordname)-1) {
    toksz = sizeof(wordname)-1;
  }

  memcpy(wordname+0,buf_ptr,toksz);
}

static void define_noname(void)
{
  start_compiling();
}

static void finish_word(void)
{
  if (!forth_state) {
    /* set error! */
    fprintf(stderr, "finish_word when not COMPILING!\n");
    return;
  }

  register int32_t emit_curr = emit_top;
  emit_stack_top--;

  register int32_t emit_base;
  if (emit_stack_top == 0) {
    emit_base = emit_ptr;
  } else {
    emit_base = emit_top;
  }

  register int32_t emit_size = emit_curr-emit_base;
  if (!enough_heap(emit_size+1)) {
    fprintf(stderr, "not enough heap space!\n");
    return;
  }

  int32_t heap_top = curr_dict->heap_top;
  register int32_t heap_ptr = heap_top;

  memcpy(forth_heap+heap_ptr, forth_heap+emit_base, emit_size*sizeof(forth_heap[0]));
  heap_ptr += emit_size;

  union forth_instruction instr;
  instr.whole = 0;
  instr.bytes[0] = FORTH_VM_RETURN;
  forth_heap[heap_ptr] = instr.whole;
  heap_ptr++;

  curr_dict->heap_top = heap_ptr;

  if (forth_state) {
    union forth_instruction instr;
    instr.whole = 0;
    instr.bytes[0] = FORTH_VM_PUSHADDR;
    emit_word(instr.whole);
    emit_word(heap_top);
  } else if (wordname[0] != '\0') {
    dict_add(curr_dict, wordname, 0, heap_top);
  } else {
    pushaddr(heap_top);
  }
}



