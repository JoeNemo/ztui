

/*
  This program and the accompanying materials are
  made available under the terms of the Eclipse Public License v2.0 which accompanies
  this distribution, and is available at https://www.eclipse.org/legal/epl-v20.html

  SPDX-License-Identifier: EPL-2.0

  Copyright Contributors to the Zowe Project.
*/

/*
  ncmem — Memory Viewer / Hex Dump Browser.
           ncurses-based TUI using nctui framework.

  Displays memory in traditional hex dump format with:
    - Address, offset, 4 groups of 4 hex bytes, EBCDIC text
    - Address heuristic: values that look like addresses are
      highlighted and clickable (pushes a new page)
    - Scrolling fetches additional pages on demand
    - Recovery-protected reads for graceful handling of unmapped pages

  Memory source is abstracted: currently reads own address space,
  but the MemReader interface supports future cross-memory via
  ZIS, ptrace, or other mechanisms.

  Future hooks:
    - DSECT/struct mapping overlay
    - Disassembly view
    - COBOL copybook mapping
    - 24-bit address mode awareness

  Usage:
    ncmem [address] [length]
      address  - hex address to start from (default: PSA = 0)
      length   - bytes to display initially (default: 4096 = 1 page)

    Commands:
      G address     - Go to hex address
      ASID nnnn     - Set target ASID (hex)
      REFRESH / F5  - Re-read memory from source
      CVT           - Jump to CVT
      GDA           - Jump to GDA
      PSA           - Jump to PSA (address 0)
      NP actions:
        S / Enter   - If row contains a detected address, navigate to it
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "nctui.h"
#include "zowetypes.h"
#include "zos.h"
#include "recovery.h"
#include "printables_for_dump.h"

/* z/OS EBCDIC-to-ASCII conversion */
#pragma runopts("FILETAG(AUTOCVT,AUTOTAG)")

/* ----------------------------------------------------------------
   Memory Reader abstraction
   ---------------------------------------------------------------- */

#define MEMRD_OK          0
#define MEMRD_FAULT      -1   /* unmapped or protected */
#define MEMRD_NOACCESS   -2   /* no authority (cross-memory) */
#define MEMRD_UNSUPPORTED -3

typedef struct MemReader_tag {
  /* Read 'length' bytes from 'address' in address space 'asid'
     into 'buffer'.  Returns MEMRD_OK or error code.
     'bytesRead' set to actual bytes read (may be partial on fault). */
  int (*read)(struct MemReader_tag *self,
              uint64_t address, int asid, void *buffer,
              int length, int *bytesRead);
  void *ctx;   /* implementation-specific context */
} MemReader;

/* ----------------------------------------------------------------
   Local address space reader — uses direct pointer dereference
   protected by recovery (ESPIE/ESTAE).
   Only works for ASID == current or ASID == 0 (meaning "self").
   ---------------------------------------------------------------- */

static volatile int gFaulted;

static void localReadAnalysis(struct RecoveryContext_tag * __ptr32 context,
                              SDWA * __ptr32 sdwa,
                              void * __ptr32 userData) {
  /* Signal that the memory read faulted */
  gFaulted = 1;
}

static int localRead(MemReader *self,
                     uint64_t address, int asid, void *buffer,
                     int length, int *bytesRead) {
  *bytesRead = 0;

  /* For now, only support our own address space */
  if (asid != 0) {
    /* ASID 0 means "current", which is all we can do without
       cross-memory services */
    return MEMRD_UNSUPPORTED;
  }

  int recoveryOK = recoveryIsRouterEstablished();
  if (!recoveryOK) {
    recoveryEstablishRouter(RCVR_ROUTER_FLAG_NONE);
  }

  /* Read in 256-byte chunks, catching faults per chunk */
  int offset = 0;
  while (offset < length) {
    int chunk = length - offset;
    if (chunk > 256) chunk = 256;

    gFaulted = 0;
    int pushRC = recoveryPush("memread",
                              RCVR_FLAG_RETRY | RCVR_FLAG_DELETE_ON_RETRY,
                              NULL,
                              localReadAnalysis, NULL,
                              NULL, NULL);
    if (pushRC == RC_RCV_OK) {
      /* Protected read */
      char *src = (char *)(uintptr_t)address + offset;
      memcpy((char *)buffer + offset, src, chunk);
      recoveryPop();
      offset += chunk;
      *bytesRead = offset;
    } else if (pushRC == RC_RCV_ABENDED) {
      /* Fault — fill this chunk with 0xCC pattern and continue */
      memset((char *)buffer + offset, 0xCC, chunk);
      offset += chunk;
      *bytesRead = offset;
      /* Could break here if we want to stop at first fault,
         but continuing gives a better picture */
    } else {
      break;
    }
  }

  return (*bytesRead > 0) ? MEMRD_OK : MEMRD_FAULT;
}

static MemReader gLocalReader = { localRead, NULL };

/* ----------------------------------------------------------------
   Memory range descriptor — what we know about the virtual
   storage layout from GDA
   ---------------------------------------------------------------- */

typedef struct MemRange_tag {
  uint64_t base;
  uint64_t size;
  char     label[16];
} MemRange;

#define MAX_RANGES 16

typedef struct MemLayout_tag {
  MemRange ranges[MAX_RANGES];
  int      count;
  int      loaded;
} MemLayout;

static MemLayout gLayout;

static void loadMemLayout(MemReader *reader) {
  if (gLayout.loaded) return;
  gLayout.loaded = 1;
  gLayout.count = 0;

  /* Read CVT pointer from PSA+0x10 */
  uint32_t cvtAddr = 0;
  int br = 0;
  if (reader->read(reader, 0x10, 0, &cvtAddr, 4, &br) != MEMRD_OK)
    return;

  /* Read GDA pointer from CVT+0x230 */
  uint32_t gdaAddr = 0;
  if (reader->read(reader, (uint64_t)cvtAddr + 0x230, 0, &gdaAddr, 4, &br) != MEMRD_OK)
    return;

  /* Read GDA fields */
  GDA gdaBuf;
  if (reader->read(reader, (uint64_t)gdaAddr, 0, &gdaBuf, sizeof(gdaBuf), &br) != MEMRD_OK)
    return;

  /* Verify eyecatcher */
  if (memcmp(gdaBuf.gdaid, "\xC7\xC4\xC1\x40", 4) != 0)  /* "GDA " in EBCDIC */
    return;

  int i = 0;
  /* Nucleus / PSA */
  gLayout.ranges[i].base = 0;
  gLayout.ranges[i].size = 0x1000;
  memcpy(gLayout.ranges[i].label, "PSA", 4);
  i++;

  if ((uint32_t)(uintptr_t)gdaBuf.gdacsa) {
    gLayout.ranges[i].base = (uint32_t)(uintptr_t)gdaBuf.gdacsa;
    gLayout.ranges[i].size = gdaBuf.gdacsasz;
    memcpy(gLayout.ranges[i].label, "CSA", 4);
    i++;
  }
  if ((uint32_t)(uintptr_t)gdaBuf.gdaecsa) {
    gLayout.ranges[i].base = (uint32_t)(uintptr_t)gdaBuf.gdaecsa;
    gLayout.ranges[i].size = gdaBuf.gdaecsas;
    memcpy(gLayout.ranges[i].label, "ECSA", 5);
    i++;
  }
  if ((uint32_t)(uintptr_t)gdaBuf.gdasqa) {
    gLayout.ranges[i].base = (uint32_t)(uintptr_t)gdaBuf.gdasqa;
    gLayout.ranges[i].size = gdaBuf.gdasqasz;
    memcpy(gLayout.ranges[i].label, "SQA", 4);
    i++;
  }
  if ((uint32_t)(uintptr_t)gdaBuf.gdaesqa) {
    gLayout.ranges[i].base = (uint32_t)(uintptr_t)gdaBuf.gdaesqa;
    gLayout.ranges[i].size = gdaBuf.gdaesqas;
    memcpy(gLayout.ranges[i].label, "ESQA", 5);
    i++;
  }
  if ((uint32_t)(uintptr_t)gdaBuf.gdapvt) {
    gLayout.ranges[i].base = (uint32_t)(uintptr_t)gdaBuf.gdapvt;
    gLayout.ranges[i].size = gdaBuf.gdapvtsz;
    memcpy(gLayout.ranges[i].label, "LPVT", 5);
    i++;
  }
  if ((uint32_t)(uintptr_t)gdaBuf.gdaepvt) {
    gLayout.ranges[i].base = (uint32_t)(uintptr_t)gdaBuf.gdaepvt;
    gLayout.ranges[i].size = gdaBuf.gdaepvts;
    memcpy(gLayout.ranges[i].label, "EPVT", 5);
    i++;
  }
  gLayout.count = i;
}

/* Heuristic: does a 4-byte value look like a 31-bit address?
   Must be non-zero, high bit may be set (AMODE 31 flag),
   and the 31-bit address should fall in a known range. */
static int looksLikeAddress31(uint32_t val) {
  if (val == 0) return 0;
  uint32_t addr = val & 0x7FFFFFFF;  /* strip AMODE bit */
  if (addr < 0x1000 && addr != 0) return 0;  /* too low, probably not a pointer */

  /* Check against known ranges */
  for (int i = 0; i < gLayout.count; i++) {
    uint64_t base = gLayout.ranges[i].base;
    uint64_t end  = base + gLayout.ranges[i].size;
    if (addr >= base && addr < end) return 1;
  }

  /* Also accept addresses in common system areas even without exact range */
  if (addr >= 0x1000 && addr < 0x80000000) return 1;

  return 0;
}

/* For 8-byte values, check if it looks like a 64-bit address */
static int looksLikeAddress64(uint64_t val) {
  if (val == 0) return 0;
  /* On z/OS, 64-bit addresses above the bar start at 0x0000_0001_0000_0000 */
  if (val > 0x100000000ULL && val < 0x7FFFFFFFFFFFFFFULL) return 1;
  /* If it fits in 31 bits, delegate to 31-bit check */
  if (val <= 0xFFFFFFFF) return looksLikeAddress31((uint32_t)val);
  return 0;
}

/* ----------------------------------------------------------------
   Data model
   ---------------------------------------------------------------- */

#define PAGE_SIZE          4096
#define BYTES_PER_ROW      16
#define MAX_CACHED_PAGES   256
#define INITIAL_PAGES      1

typedef struct CachedPage_tag {
  uint64_t  address;         /* base address of this page */
  char      data[PAGE_SIZE];
  int       valid;           /* 1 = data read, 0 = not yet */
  int       faulted;         /* 1 = read faulted (partial or full) */
} CachedPage;

typedef struct MemViewData_tag {
  /* View parameters */
  uint64_t    baseAddress;     /* starting address user asked for */
  int         asid;            /* target ASID (0 = current) */

  /* Cache */
  CachedPage  pages[MAX_CACHED_PAGES];
  int         pageCount;
  int         totalRows;       /* rows across all cached pages */

  /* Memory reader */
  MemReader  *reader;

  /* Address heuristic */
  MemLayout  *layout;

  /* TUI */
  NcTuiTable *tui;
} MemViewData;

static MemViewData gMemData;

/* Ensure a page is cached for the given address.
   Returns pointer to the cached page, or NULL if cache is full. */
static CachedPage *ensurePage(MemViewData *d, uint64_t pageAddr) {
  pageAddr &= ~(uint64_t)(PAGE_SIZE - 1);  /* align to page */

  /* Check if already cached */
  for (int i = 0; i < d->pageCount; i++) {
    if (d->pages[i].address == pageAddr)
      return &d->pages[i];
  }

  /* Need to fetch */
  if (d->pageCount >= MAX_CACHED_PAGES) return NULL;

  CachedPage *pg = &d->pages[d->pageCount];
  pg->address = pageAddr;
  pg->valid = 1;

  int bytesRead = 0;
  int rc = d->reader->read(d->reader, pageAddr, d->asid,
                           pg->data, PAGE_SIZE, &bytesRead);
  if (rc != MEMRD_OK || bytesRead < PAGE_SIZE) {
    pg->faulted = 1;
    /* Zero-fill unread portion */
    if (bytesRead < PAGE_SIZE)
      memset(pg->data + bytesRead, 0xCC, PAGE_SIZE - bytesRead);
  }

  d->pageCount++;
  d->totalRows = d->pageCount * (PAGE_SIZE / BYTES_PER_ROW);
  return pg;
}

/* Get a byte from the cached data.  Returns -1 if not available. */
static int getByte(MemViewData *d, uint64_t address) {
  uint64_t pageAddr = address & ~(uint64_t)(PAGE_SIZE - 1);
  int offset = (int)(address - pageAddr);

  CachedPage *pg = ensurePage(d, pageAddr);
  if (!pg) return -1;
  return (unsigned char)pg->data[offset];
}

/* Get a 4-byte big-endian value from cache.  Returns 0 and sets *ok=0 if unavailable. */
static uint32_t getWord(MemViewData *d, uint64_t address, int *ok) {
  *ok = 1;
  uint32_t val = 0;
  for (int i = 0; i < 4; i++) {
    int b = getByte(d, address + i);
    if (b < 0) { *ok = 0; return 0; }
    val = (val << 8) | (unsigned char)b;
  }
  return val;
}

/* Initialize view at a given address */
static void initView(MemViewData *d, uint64_t address, int pages) {
  d->baseAddress = address;
  d->pageCount = 0;
  d->totalRows = 0;

  /* Pre-fetch the requested pages */
  for (int i = 0; i < pages && i < MAX_CACHED_PAGES; i++) {
    ensurePage(d, address + (uint64_t)i * PAGE_SIZE);
  }
}

/* ----------------------------------------------------------------
   Address for a display row
   ---------------------------------------------------------------- */

static uint64_t addressForRow(MemViewData *d, int row) {
  /* Each page has PAGE_SIZE/BYTES_PER_ROW rows (256 rows per 4K page) */
  int rowsPerPage = PAGE_SIZE / BYTES_PER_ROW;

  if (d->pageCount == 0) return d->baseAddress;

  /* Find which page this row is in */
  int pageIdx = row / rowsPerPage;
  int rowInPage = row % rowsPerPage;

  if (pageIdx < d->pageCount) {
    return d->pages[pageIdx].address + (uint64_t)(rowInPage * BYTES_PER_ROW);
  }

  /* Beyond cached pages — extrapolate from last page */
  uint64_t lastAddr = d->pages[d->pageCount - 1].address;
  int beyondPages = pageIdx - (d->pageCount - 1);
  return lastAddr + (uint64_t)beyondPages * PAGE_SIZE +
         (uint64_t)(rowInPage * BYTES_PER_ROW);
}

/* ----------------------------------------------------------------
   Column definitions

   NP | Address          | Offset   | Hex 0-3 | Hex 4-7 | Hex 8-B | Hex C-F | Text
   ---------------------------------------------------------------- */

enum {
  COL_NP = 0,
  COL_ADDR,
  COL_OFFSET,
  COL_HEX0,
  COL_HEX1,
  COL_HEX2,
  COL_HEX3,
  COL_TEXT,
  COL_COUNT
};

static NcTuiColumn memColumns[] = {
  { "NP",       4,  NCTUI_ALIGN_LEFT },
  { "Address",  18, NCTUI_ALIGN_LEFT },
  { "+Offset",  10, NCTUI_ALIGN_RIGHT },
  { "0-3",      12, NCTUI_ALIGN_LEFT },
  { "4-7",      12, NCTUI_ALIGN_LEFT },
  { "8-B",      12, NCTUI_ALIGN_LEFT },
  { "C-F",      12, NCTUI_ALIGN_LEFT },
  { "EBCDIC",   18, NCTUI_ALIGN_LEFT },
};

/* ----------------------------------------------------------------
   Cell formatter
   ---------------------------------------------------------------- */

static void memCellFormatter(int row, int col, char *buf, int bufLen,
                             void *userData) {
  MemViewData *d = (MemViewData *)userData;
  uint64_t addr = addressForRow(d, row);

  /* Make sure the page is cached */
  ensurePage(d, addr);

  switch (col) {
  case COL_NP:
    buf[0] = '\0';
    break;

  case COL_ADDR:
    if (addr > 0xFFFFFFFF)
      snprintf(buf, bufLen, "%016llX", (unsigned long long)addr);
    else
      snprintf(buf, bufLen, "%08llX", (unsigned long long)addr);
    break;

  case COL_OFFSET: {
    int64_t off = (int64_t)(addr - d->baseAddress);
    snprintf(buf, bufLen, "+%06llX", (unsigned long long)off);
    break;
  }

  case COL_HEX0:
  case COL_HEX1:
  case COL_HEX2:
  case COL_HEX3: {
    int group = col - COL_HEX0;
    uint64_t ga = addr + group * 4;
    char *p = buf;
    for (int i = 0; i < 4; i++) {
      int b = getByte(d, ga + i);
      if (b >= 0) {
        p += snprintf(p, bufLen - (p - buf), "%02X", b);
      } else {
        p += snprintf(p, bufLen - (p - buf), "??");
      }
    }
    /* Insert space after each byte pair for readability:
       turn "AABBCCDD" into "AABB CCDD" */
    if (strlen(buf) == 8) {
      char tmp[16];
      memcpy(tmp, buf, 4);
      tmp[4] = ' ';
      memcpy(tmp + 5, buf + 4, 4);
      tmp[9] = '\0';
      strncpy(buf, tmp, bufLen - 1);
      buf[bufLen - 1] = '\0';
    }
    break;
  }

  case COL_TEXT: {
    char *p = buf;
    for (int i = 0; i < BYTES_PER_ROW && (p - buf) < bufLen - 1; i++) {
      int b = getByte(d, addr + i);
      if (b >= 0) {
        *p++ = (char)printableEBCDIC[b];
      } else {
        *p++ = '?';
      }
    }
    *p = '\0';
    break;
  }

  default:
    buf[0] = '\0';
    break;
  }
}

/* ----------------------------------------------------------------
   Detect clickable address in a row.
   Scans the 16 bytes at 4-byte aligned offsets for values
   that look like addresses.  Returns the first one found,
   or 0 if none.
   ---------------------------------------------------------------- */

static uint64_t detectAddress(MemViewData *d, int row) {
  uint64_t rowAddr = addressForRow(d, row);

  /* Check each 4-byte aligned word */
  for (int off = 0; off < BYTES_PER_ROW; off += 4) {
    int ok;
    uint32_t w = getWord(d, rowAddr + off, &ok);
    if (ok && looksLikeAddress31(w)) {
      return (uint64_t)(w & 0x7FFFFFFF);
    }
  }
  return 0;
}

/* ----------------------------------------------------------------
   NP action: navigate to address (drill-down)
   ---------------------------------------------------------------- */

/* Forward declaration */
static void pushMemPage(NcTuiNav *nav, MemViewData *parentData,
                        uint64_t address, int asid);

static int actionNavigate(int row, void *userData, NcTuiNav *nav) {
  MemViewData *d = (MemViewData *)userData;
  uint64_t target = detectAddress(d, row);

  if (target == 0) {
    if (d->tui)
      nctuiSetStatus(d->tui, "No address detected in this row");
    return 0;
  }

  pushMemPage(nav, d, target, d->asid);
  return 0;
}

/* ----------------------------------------------------------------
   Command handler
   ---------------------------------------------------------------- */

static int memCommandHandler(const char *command, void *userData) {
  MemViewData *d = (MemViewData *)userData;

  if (command[0] == '\0') return 0;

  /* Quit */
  if (strcmp(command, "Q") == 0 || strcmp(command, "q") == 0 ||
      strcmp(command, "QUIT") == 0 || strcmp(command, "quit") == 0)
    return 1;

  /* Go to address: G <hex> */
  if ((command[0] == 'G' || command[0] == 'g') && command[1] == ' ') {
    uint64_t addr = 0;
    const char *p = command + 2;
    while (*p == ' ') p++;
    /* Skip optional 0x prefix */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    while (*p) {
      char c = *p++;
      int nibble = -1;
      if (c >= '0' && c <= '9') nibble = c - '0';
      else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
      else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
      else break;
      addr = (addr << 4) | nibble;
    }
    /* Re-initialize view at new address */
    initView(d, addr, INITIAL_PAGES);
    d->tui->rowCount = d->totalRows;
    d->tui->scrollRow = 0;
    d->tui->selectedRow = 0;
    d->tui->cursorRow = 0;
    nctuiSetStatus(d->tui, "Address: %llX", (unsigned long long)addr);
    return 0;
  }

  /* Set ASID: ASID <hex> */
  if (strncmp(command, "ASID ", 5) == 0 || strncmp(command, "asid ", 5) == 0) {
    int asid = (int)strtol(command + 5, NULL, 16);
    d->asid = asid;
    initView(d, d->baseAddress, INITIAL_PAGES);
    d->tui->rowCount = d->totalRows;
    nctuiSetStatus(d->tui, "ASID set to %04X", asid);
    return 0;
  }

  /* Refresh */
  if (strcmp(command, "REFRESH") == 0 || strcmp(command, "refresh") == 0) {
    uint64_t savedBase = d->baseAddress;
    initView(d, savedBase, INITIAL_PAGES);
    d->tui->rowCount = d->totalRows;
    nctuiSetStatus(d->tui, "Refreshed");
    return 0;
  }

  /* CVT shortcut */
  if (strcmp(command, "CVT") == 0 || strcmp(command, "cvt") == 0) {
    int ok;
    uint32_t cvtAddr = getWord(d, 0x10, &ok);
    if (!ok) {
      /* Try reading PSA fresh */
      ensurePage(d, 0);
      cvtAddr = getWord(d, 0x10, &ok);
    }
    if (ok && cvtAddr) {
      initView(d, (uint64_t)cvtAddr, INITIAL_PAGES);
      d->tui->rowCount = d->totalRows;
      d->tui->scrollRow = 0;
      d->tui->selectedRow = 0;
      d->tui->cursorRow = 0;
      nctuiSetStatus(d->tui, "CVT at %08X", cvtAddr);
    } else {
      nctuiSetStatus(d->tui, "Cannot read CVT address from PSA");
    }
    return 0;
  }

  /* GDA shortcut */
  if (strcmp(command, "GDA") == 0 || strcmp(command, "gda") == 0) {
    int ok;
    uint32_t cvtAddr = getWord(d, 0x10, &ok);
    if (ok && cvtAddr) {
      ensurePage(d, (uint64_t)cvtAddr);
      uint32_t gdaAddr = getWord(d, (uint64_t)cvtAddr + 0x230, &ok);
      if (ok && gdaAddr) {
        initView(d, (uint64_t)gdaAddr, INITIAL_PAGES);
        d->tui->rowCount = d->totalRows;
        d->tui->scrollRow = 0;
        d->tui->selectedRow = 0;
        d->tui->cursorRow = 0;
        nctuiSetStatus(d->tui, "GDA at %08X", gdaAddr);
        return 0;
      }
    }
    nctuiSetStatus(d->tui, "Cannot locate GDA");
    return 0;
  }

  /* PSA shortcut */
  if (strcmp(command, "PSA") == 0 || strcmp(command, "psa") == 0) {
    initView(d, 0, INITIAL_PAGES);
    d->tui->rowCount = d->totalRows;
    d->tui->scrollRow = 0;
    d->tui->selectedRow = 0;
    d->tui->cursorRow = 0;
    nctuiSetStatus(d->tui, "PSA at 00000000");
    return 0;
  }

  /* Otherwise treat as a hex address (no G prefix required) */
  {
    const char *p = command;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    int allHex = 1;
    int len = 0;
    for (const char *q = p; *q; q++) {
      char c = *q;
      if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
          (c >= 'a' && c <= 'f'))
        len++;
      else
        { allHex = 0; break; }
    }
    if (allHex && len >= 2 && len <= 16) {
      uint64_t addr = 0;
      while (*p) {
        char c = *p++;
        int nibble = 0;
        if (c >= '0' && c <= '9') nibble = c - '0';
        else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
        addr = (addr << 4) | nibble;
      }
      initView(d, addr, INITIAL_PAGES);
      d->tui->rowCount = d->totalRows;
      d->tui->scrollRow = 0;
      d->tui->selectedRow = 0;
      d->tui->cursorRow = 0;
      nctuiSetStatus(d->tui, "Address: %llX", (unsigned long long)addr);
      return 0;
    }
  }

  nctuiSetStatus(d->tui, "Unknown command: %s", command);
  return 0;
}

/* ----------------------------------------------------------------
   Refresh handler (F5)
   ---------------------------------------------------------------- */

static int memRefreshHandler(void *userData) {
  MemViewData *d = (MemViewData *)userData;
  uint64_t savedBase = d->baseAddress;
  int savedAsid = d->asid;

  d->pageCount = 0;
  d->totalRows = 0;
  initView(d, savedBase, INITIAL_PAGES);

  return d->totalRows;
}

/* ----------------------------------------------------------------
   Scroll extension — when user scrolls beyond cached data,
   fetch more pages.  Called from the cell formatter when
   ensurePage() expands the cache.
   ---------------------------------------------------------------- */

/* (ensurePage already handles this — it extends the cache on demand.
    The tui rowCount is updated after each ensurePage call in the
    cell formatter to allow infinite scrolling.) */

/* ----------------------------------------------------------------
   Push a new memory page onto the navigator stack
   ---------------------------------------------------------------- */

/* Per-page data for drill-down pages.
   We allocate these dynamically since the nav stack copies the page struct
   but we need stable MemViewData storage. */

#define MAX_DRILLDOWN 32
static MemViewData gDrillData[MAX_DRILLDOWN];
static int gDrillCount = 0;

static void pushMemPage(NcTuiNav *nav, MemViewData *parentData,
                        uint64_t address, int asid) {
  if (gDrillCount >= MAX_DRILLDOWN) {
    nctuiSetStatus(parentData->tui, "Navigation stack full");
    return;
  }

  MemViewData *dd = &gDrillData[gDrillCount++];
  memset(dd, 0, sizeof(*dd));
  dd->reader = parentData->reader;
  dd->layout = parentData->layout;
  dd->asid = asid;

  initView(dd, address, INITIAL_PAGES);

  NcTuiPage page;
  char breadcrumb[32];
  snprintf(breadcrumb, sizeof(breadcrumb), "%08llX",
           (unsigned long long)address);
  nctuiPageInitTable(&page, breadcrumb);
  nctuiSetColumns(&page.table, memColumns, COL_COUNT, 3);

  char title[64];
  snprintf(title, sizeof(title), "MEMORY @ %08llX  ASID=%04X",
           (unsigned long long)address, asid);
  nctuiSetTitle(&page.table, title);

  page.table.rowCount = dd->totalRows;
  page.table.cellFormatter = memCellFormatter;
  page.table.commandHandler = memCommandHandler;
  page.table.refreshHandler = memRefreshHandler;
  page.table.userData = dd;

  nctuiAddAction(&page.table, 'S', "Navigate",
                 NCTUI_ACTION_DEFAULT | NCTUI_ACTION_DRILLDOWN,
                 actionNavigate);

  nctuiNavPush(nav, &page);

  /* Update tui pointer after push (page was copied into stack) */
  dd->tui = &nav->stack[nav->depth].table;
}

/* ----------------------------------------------------------------
   Main
   ---------------------------------------------------------------- */

int main(int argc, char *argv[]) {
  uint64_t startAddr = 0;
  int startPages = INITIAL_PAGES;

  /* Parse command line */
  if (argc >= 2) {
    const char *p = argv[1];
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    while (*p) {
      char c = *p++;
      int nibble = 0;
      if (c >= '0' && c <= '9') nibble = c - '0';
      else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
      else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
      else break;
      startAddr = (startAddr << 4) | nibble;
    }
  }
  if (argc >= 3) {
    int len = (int)strtol(argv[2], NULL, 0);
    if (len > 0)
      startPages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
  }

  /* Initialize memory subsystem */
  memset(&gMemData, 0, sizeof(gMemData));
  memset(&gLayout, 0, sizeof(gLayout));
  gMemData.reader = &gLocalReader;
  gMemData.layout = &gLayout;
  gMemData.asid = 0;

  /* Load GDA-based memory layout for address heuristic */
  loadMemLayout(gMemData.reader);

  /* Initialize view */
  initView(&gMemData, startAddr, startPages);

  /* Set up navigator */
  NcTuiNav nav;
  nctuiNavInit(&nav);

  NcTuiPage memPage;
  nctuiPageInitTable(&memPage, "MEM");
  nctuiSetColumns(&memPage.table, memColumns, COL_COUNT, 3);

  char title[64];
  snprintf(title, sizeof(title), "ZMEM - MEMORY VIEWER @ %08llX",
           (unsigned long long)startAddr);
  nctuiSetTitle(&memPage.table, title);

  memPage.table.rowCount = gMemData.totalRows;
  memPage.table.cellFormatter = memCellFormatter;
  memPage.table.commandHandler = memCommandHandler;
  memPage.table.refreshHandler = memRefreshHandler;
  memPage.table.userData = &gMemData;

  /* NP actions */
  nctuiAddAction(&memPage.table, 'S', "Navigate",
                 NCTUI_ACTION_DEFAULT | NCTUI_ACTION_DRILLDOWN,
                 actionNavigate);

  nctuiNavPush(&nav, &memPage);
  gMemData.tui = &nav.stack[0].table;

  nctuiNavRun(&nav);
  nctuiNavTerm(&nav);

  /* Cleanup: recovery router */
  if (recoveryIsRouterEstablished())
    recoveryRemoveRouter();

  return 0;
}

/*
  This program and the accompanying materials are
  made available under the terms of the Eclipse Public License v2.0 which accompanies
  this distribution, and is available at https://www.eclipse.org/legal/epl-v20.html

  SPDX-License-Identifier: EPL-2.0

  Copyright Contributors to the Zowe Project.
*/
