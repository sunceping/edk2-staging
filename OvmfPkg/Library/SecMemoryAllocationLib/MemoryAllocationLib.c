#include <PiPei.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>

//
// Definitions for Runtime Memory Operations
//
#define RT_PAGE_SIZE   0x400    // 1024 Byte
#define RT_PAGE_MASK   0x3FF
#define RT_PAGE_SHIFT  10

#define RT_SIZE_TO_PAGES(a)  (((a) >> RT_PAGE_SHIFT) + (((a) & RT_PAGE_MASK) ? 1 : 0))
#define RT_PAGES_TO_SIZE(a)  ((a) << RT_PAGE_SHIFT)

//
// Page Flag Definitions
//
#define RT_PAGE_FREE  0x00000000
#define RT_PAGE_USED  0x00000001

#define MIN_REQUIRED_BLOCKS  600

//
// Memory Page Table
//
typedef struct {
  UINT32    StartPageOffset;    // Offset of the starting page allocated.
                                // Only available for USED pages.
  UINT32    PageFlag;           // Page Attributes.
} RT_MEMORY_PAGE_ENTRY;

typedef struct {
  UINT32                   PageCount;
  UINT32                   LastEmptyPageOffset;
  UINT8                   *DataAreaBase;       // Pointer to data Area.
  RT_MEMORY_PAGE_ENTRY    Pages[1];            // Page Table Entries.
} RT_MEMORY_PAGE_TABLE;

//
// Global Page Table for Runtime Cryptographic Provider.
//
RT_MEMORY_PAGE_TABLE  *mRTPageTable = (RT_MEMORY_PAGE_TABLE  *)(UINTN)(FixedPcdGet32(PcdOvmfSecScratchMemoryBase) + 0x400);

/**
  Initializes pre-allocated memory pointed by ScratchBuffer for subsequent
  runtime use.

  @param[in, out]  ScratchBuffer      Pointer to user-supplied memory buffer.
  @param[in]       ScratchBufferSize  Size of supplied buffer in bytes.

  @retval EFI_SUCCESS  Successful initialization.

**/
STATIC
EFI_STATUS
InitializeScratchMemory (
  IN OUT  UINT8  *ScratchBuffer,
  IN      UINTN  ScratchBufferSize
  )
{
  UINTN  Index;
  UINTN  MemorySize;
  UINT8  *DataAreaBase;

  //
  // Parameters Checking
  //
  if (ScratchBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (ScratchBufferSize < MIN_REQUIRED_BLOCKS * 1024) {
    return EFI_BUFFER_TOO_SMALL;
  }

  // mRTPageTable = (RT_MEMORY_PAGE_TABLE *)ScratchBuffer;
  ASSERT ((UINT8 *)mRTPageTable == ScratchBuffer);

  //
  // Initialize Internal Page Table for Memory Management
  //
  SetMem (mRTPageTable, ScratchBufferSize, 0xFF);
  MemorySize = ScratchBufferSize - sizeof (RT_MEMORY_PAGE_TABLE) + sizeof (RT_MEMORY_PAGE_ENTRY);

  mRTPageTable->PageCount           = MemorySize / (RT_PAGE_SIZE + sizeof (RT_MEMORY_PAGE_ENTRY));
  mRTPageTable->LastEmptyPageOffset = 0x0;

  for (Index = 0; Index < mRTPageTable->PageCount; Index++) {
    mRTPageTable->Pages[Index].PageFlag        = RT_PAGE_FREE;
    mRTPageTable->Pages[Index].StartPageOffset = 0;
  }

  DataAreaBase = ScratchBuffer + sizeof (RT_MEMORY_PAGE_TABLE) +
                 (mRTPageTable->PageCount - 1) * sizeof (RT_MEMORY_PAGE_ENTRY);
  
  mRTPageTable->DataAreaBase = ALIGN_POINTER(DataAreaBase, 0x1000);

  return EFI_SUCCESS;
}

/**
  Look-up Free memory Region for object allocation.

  @param[in]  AllocationSize  Bytes to be allocated.

  @return  Return available page offset for object allocation.

**/
STATIC
UINTN
LookupFreeMemRegion (
  IN  UINTN  AllocationSize
  )
{
  UINTN  StartPageIndex;
  UINTN  Index;
  UINTN  SubIndex;
  UINTN  ReqPages;

  StartPageIndex = RT_SIZE_TO_PAGES (mRTPageTable->LastEmptyPageOffset);
  ReqPages       = RT_SIZE_TO_PAGES (AllocationSize);
  if (ReqPages > mRTPageTable->PageCount) {
    //
    // No enough region for object allocation.
    //
    return (UINTN)(-1);
  }

  //
  // Look up the free memory region with in current memory map table.
  //
  for (Index = StartPageIndex; Index <= (mRTPageTable->PageCount - ReqPages); ) {
    //
    // Check consecutive ReqPages pages.
    //
    for (SubIndex = 0; SubIndex < ReqPages; SubIndex++) {
      if ((mRTPageTable->Pages[SubIndex + Index].PageFlag & RT_PAGE_USED) != 0) {
        break;
      }
    }

    if (SubIndex == ReqPages) {
      //
      // Succeed! Return the Starting Offset.
      //
      return RT_PAGES_TO_SIZE (Index);
    }

    //
    // Failed! Skip current free memory pages and adjacent Used pages
    //
    while ((mRTPageTable->Pages[SubIndex + Index].PageFlag & RT_PAGE_USED) != 0) {
      SubIndex++;
    }

    Index += SubIndex;
  }

  //
  // Look up the free memory region from the beginning of the memory table
  // until the StartCursorOffset
  //
  if (ReqPages > StartPageIndex) {
    //
    // No enough region for object allocation.
    //
    return (UINTN)(-1);
  }

  for (Index = 0; Index < (StartPageIndex - ReqPages); ) {
    //
    // Check Consecutive ReqPages Pages.
    //
    for (SubIndex = 0; SubIndex < ReqPages; SubIndex++) {
      if ((mRTPageTable->Pages[SubIndex + Index].PageFlag & RT_PAGE_USED) != 0) {
        break;
      }
    }

    if (SubIndex == ReqPages) {
      //
      // Succeed! Return the Starting Offset.
      //
      return RT_PAGES_TO_SIZE (Index);
    }

    //
    // Failed! Skip current adjacent Used pages
    //
    while ((SubIndex < (StartPageIndex - ReqPages)) &&
           ((mRTPageTable->Pages[SubIndex + Index].PageFlag & RT_PAGE_USED) != 0))
    {
      SubIndex++;
    }

    Index += SubIndex;
  }

  //
  // No available region for object allocation!
  //
  return (UINTN)(-1);
}

/**
  Allocates a buffer at runtime phase.

  @param[in]  AllocationSize    Bytes to be allocated.

  @return  A pointer to the allocated buffer or NULL if allocation fails.

**/
STATIC
VOID *
AllocateMem (
  IN  UINTN  AllocationSize
  )
{
  UINT8  *AllocPtr;
  UINTN  ReqPages;
  UINTN  Index;
  UINTN  StartPage;
  UINTN  AllocOffset;

  AllocPtr = NULL;
  ReqPages = 0;

  //
  // Look for available consecutive memory region starting from LastEmptyPageOffset.
  // If no proper memory region found, look up from the beginning.
  // If still not found, return NULL to indicate failed allocation.
  //
  AllocOffset = LookupFreeMemRegion (AllocationSize);
  if (AllocOffset == (UINTN)(-1)) {
    return NULL;
  }

  //
  // Allocates consecutive memory pages with length of Size. Update the page
  // table status. Returns the starting address.
  //
  ReqPages  = RT_SIZE_TO_PAGES (AllocationSize);
  AllocPtr  = mRTPageTable->DataAreaBase + AllocOffset;
  StartPage = RT_SIZE_TO_PAGES (AllocOffset);
  Index     = 0;
  while (Index < ReqPages) {
    mRTPageTable->Pages[StartPage + Index].PageFlag       |= RT_PAGE_USED;
    mRTPageTable->Pages[StartPage + Index].StartPageOffset = AllocOffset;

    Index++;
  }

  mRTPageTable->LastEmptyPageOffset = AllocOffset + RT_PAGES_TO_SIZE (ReqPages);

  ZeroMem (AllocPtr, AllocationSize);

  //
  // Returns a void pointer to the allocated space
  //
  return AllocPtr;
}

/**
  Frees a buffer that was previously allocated at runtime phase.

  @param[in]  Buffer  Pointer to the buffer to free.

**/
STATIC
VOID
FreeMem (
  IN  VOID  *Buffer
  )
{
  UINTN  StartOffset;
  UINTN  StartPageIndex;

  StartOffset    = (UINTN)Buffer - (UINTN)mRTPageTable->DataAreaBase;
  StartPageIndex = RT_SIZE_TO_PAGES (mRTPageTable->Pages[RT_SIZE_TO_PAGES (StartOffset)].StartPageOffset);

  while (StartPageIndex < mRTPageTable->PageCount) {
    if (((mRTPageTable->Pages[StartPageIndex].PageFlag & RT_PAGE_USED) != 0) &&
        (mRTPageTable->Pages[StartPageIndex].StartPageOffset == StartOffset))
    {
      //
      // Free this page
      //
      mRTPageTable->Pages[StartPageIndex].PageFlag       &= ~RT_PAGE_USED;
      mRTPageTable->Pages[StartPageIndex].PageFlag       |= RT_PAGE_FREE;
      mRTPageTable->Pages[StartPageIndex].StartPageOffset = 0;

      StartPageIndex++;
    } else {
      break;
    }
  }

  return;
}

/**
  Allocates one or more 4KB pages of type EfiBootServicesData.

  Allocates the number of 4KB pages of type EfiBootServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocatePages (
  IN UINTN  Pages
  )
{
  return AllocateMem(EFI_PAGES_TO_SIZE(Pages));
}

/**
  Allocates one or more 4KB pages of type EfiRuntimeServicesData.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateRuntimePages (
  IN UINTN  Pages
  )
{
  return AllocateMem(EFI_PAGES_TO_SIZE(Pages));
}

/**
  Allocates one or more 4KB pages of type EfiReservedMemoryType.

  Allocates the number of 4KB pages of type EfiReservedMemoryType and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateReservedPages (
  IN UINTN  Pages
  )
{
  return AllocateMem(EFI_PAGES_TO_SIZE(Pages));
}

/**
  Frees one or more 4KB pages that were previously allocated with one of the page allocation
  functions in the Memory Allocation Library.

  Frees the number of 4KB pages specified by Pages from the buffer specified by Buffer.  Buffer
  must have been allocated on a previous call to the page allocation services of the Memory
  Allocation Library.  If it is not possible to free allocated pages, then this function will
  perform no actions.

  If Buffer was not allocated with a page allocation function in the Memory Allocation Library,
  then ASSERT().
  If Pages is zero, then ASSERT().

  @param  Buffer                Pointer to the buffer of pages to free.
  @param  Pages                 The number of 4 KB pages to free.

**/
VOID
EFIAPI
FreePages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  FreeMem(Buffer);
}


/**
  Allocates one or more 4KB pages of type EfiBootServicesData at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiBootServicesData with an
  alignment specified by Alignment.  The allocated buffer is returned.  If Pages is 0, then NULL is
  returned.  If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  Alignment             The requested alignment of the allocation.  Must be a power of two.
                                If Alignment is zero, then byte alignment is used.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateAlignedPages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Allocates one or more 4KB pages of type EfiRuntimeServicesData at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiRuntimeServicesData with an
  alignment specified by Alignment.  The allocated buffer is returned.  If Pages is 0, then NULL is
  returned.  If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  Alignment             The requested alignment of the allocation.  Must be a power of two.
                                If Alignment is zero, then byte alignment is used.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateAlignedRuntimePages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Allocates one or more 4KB pages of type EfiReservedMemoryType at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiReservedMemoryType with an
  alignment specified by Alignment.  The allocated buffer is returned.  If Pages is 0, then NULL is
  returned.  If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  Alignment             The requested alignment of the allocation.  Must be a power of two.
                                If Alignment is zero, then byte alignment is used.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateAlignedReservedPages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Frees one or more 4KB pages that were previously allocated with one of the aligned page
  allocation functions in the Memory Allocation Library.

  Frees the number of 4KB pages specified by Pages from the buffer specified by Buffer.  Buffer
  must have been allocated on a previous call to the aligned page allocation services of the Memory
  Allocation Library.  If it is not possible to free allocated pages, then this function will
  perform no actions.

  If Buffer was not allocated with an aligned page allocation function in the Memory Allocation
  Library, then ASSERT().
  If Pages is zero, then ASSERT().

  @param  Buffer                Pointer to the buffer of pages to free.
  @param  Pages                 The number of 4 KB pages to free.

**/
VOID
EFIAPI
FreeAlignedPages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
}

/**
  Allocates a buffer of type EfiBootServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiBootServicesData and returns a
  pointer to the allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is
  returned.  If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  )
{
  return AllocateMem(AllocationSize);
}

/**
  Allocates a buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData and returns
  a pointer to the allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is
  returned.  If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateRuntimePool (
  IN UINTN  AllocationSize
  )
{
  return AllocateMem(AllocationSize);
}

/**
  Allocates a buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType and returns
  a pointer to the allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is
  returned.  If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateReservedPool (
  IN UINTN  AllocationSize
  )
{
  return AllocateMem(AllocationSize);
}

/**
  Allocates and zeros a buffer of type EfiBootServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiBootServicesData, clears the
  buffer with zeros, and returns a pointer to the allocated buffer.  If AllocationSize is 0, then a
  valid buffer of 0 size is returned.  If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate and zero.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  )
{
  VOID *Ptr;

  Ptr = AllocateMem(AllocationSize);
  if (Ptr != NULL) {
    ZeroMem(Ptr, AllocationSize);
  }

  return Ptr;
}

/**
  Allocates and zeros a buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData, clears the
  buffer with zeros, and returns a pointer to the allocated buffer.  If AllocationSize is 0, then a
  valid buffer of 0 size is returned.  If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate and zero.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateRuntimeZeroPool (
  IN UINTN  AllocationSize
  )
{
  return AllocateZeroPool (AllocationSize);
}

/**
  Allocates and zeros a buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType, clears the
  buffer with zeros, and returns a pointer to the allocated buffer.  If AllocationSize is 0, then a
  valid buffer of 0 size is returned.  If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate and zero.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateReservedZeroPool (
  IN UINTN  AllocationSize
  )
{
  return AllocateZeroPool (AllocationSize);
}

/**
  Copies a buffer to an allocated buffer of type EfiBootServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiBootServicesData, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is returned.  If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  AllocationSize        The number of bytes to allocate and zero.
  @param  Buffer                The buffer to copy to the allocated buffer.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Copies a buffer to an allocated buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is returned.  If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  AllocationSize        The number of bytes to allocate and zero.
  @param  Buffer                The buffer to copy to the allocated buffer.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateRuntimeCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Copies a buffer to an allocated buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is returned.  If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  AllocationSize        The number of bytes to allocate and zero.
  @param  Buffer                The buffer to copy to the allocated buffer.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
AllocateReservedCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Reallocates a buffer of type EfiBootServicesData.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiBootServicesData.  If OldBuffer is not NULL, then the smaller of OldSize and
  NewSize bytes are copied from OldBuffer to the newly allocated buffer, and
  OldBuffer is freed.  A pointer to the newly allocated buffer is returned.
  If NewSize is 0, then a valid buffer of 0 size is  returned.  If there is not
  enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize
  is greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param  OldSize        The size, in bytes, of OldBuffer.
  @param  NewSize        The size, in bytes, of the buffer to reallocate.
  @param  OldBuffer      The buffer to copy to the allocated buffer.  This is an optional
                         parameter that may be NULL.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
ReallocatePool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Reallocates a buffer of type EfiRuntimeServicesData.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiRuntimeServicesData.  If OldBuffer is not NULL, then the smaller of OldSize and
  NewSize bytes are copied from OldBuffer to the newly allocated buffer, and
  OldBuffer is freed.  A pointer to the newly allocated buffer is returned.
  If NewSize is 0, then a valid buffer of 0 size is  returned.  If there is not
  enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize
  is greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param  OldSize        The size, in bytes, of OldBuffer.
  @param  NewSize        The size, in bytes, of the buffer to reallocate.
  @param  OldBuffer      The buffer to copy to the allocated buffer.  This is an optional
                         parameter that may be NULL.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
ReallocateRuntimePool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Reallocates a buffer of type EfiReservedMemoryType.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiReservedMemoryType.  If OldBuffer is not NULL, then the smaller of OldSize and
  NewSize bytes are copied from OldBuffer to the newly allocated buffer, and
  OldBuffer is freed.  A pointer to the newly allocated buffer is returned.
  If NewSize is 0, then a valid buffer of 0 size is  returned.  If there is not
  enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize
  is greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param  OldSize        The size, in bytes, of OldBuffer.
  @param  NewSize        The size, in bytes, of the buffer to reallocate.
  @param  OldBuffer      The buffer to copy to the allocated buffer.  This is an optional
                         parameter that may be NULL.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
EFIAPI
ReallocateReservedPool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Frees a buffer that was previously allocated with one of the pool allocation functions in the
  Memory Allocation Library.

  Frees the buffer specified by Buffer.  Buffer must have been allocated on a previous call to the
  pool allocation services of the Memory Allocation Library.  If it is not possible to free pool
  resources, then this function will perform no actions.

  If Buffer was not allocated with a pool allocation function in the Memory Allocation Library,
  then ASSERT().

  @param  Buffer                Pointer to the buffer to free.

**/
VOID
EFIAPI
FreePool (
  IN VOID  *Buffer
  )
{
  FreeMem(Buffer);
}

EFI_STATUS
EFIAPI
SecMemoryAllocationLibConstructor (
  VOID
  )
{
  InitializeScratchMemory((UINT8 *)(UINTN)(FixedPcdGet32(PcdOvmfSecScratchMemoryBase) + 0x400), SIZE_4MB - 0x400);
  return EFI_SUCCESS;
}