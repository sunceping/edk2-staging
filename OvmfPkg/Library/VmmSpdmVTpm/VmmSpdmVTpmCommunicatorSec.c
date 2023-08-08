/** @file

  Copyright (c) 2022 - 2023, Intel Corporation. All rights reserved. <BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <PiDxe.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Stub/SpdmLibStub.h>
#include <library/spdm_requester_lib.h>
#include <SpdmReturnStatus.h>
#include <IndustryStandard/VTpmTd.h>
#include <Library/VmmSpdmVTpmCommunicatorLib.h>
#include "VmmSpdmInternal.h"
#include <Library/TdxLib.h>
#include <Library/BaseCryptLib.h>
#include <IndustryStandard/Tdx.h>
#include <Library/MemEncryptTdxLib.h>

/**
 * Calculate the buffers' size of a VmmSpdmContext.
 */
STATIC
UINTN
EFIAPI
VmmSpmdCalculateSize (
  VMM_SPDM_CONTEXT_BUFFERS_SIZE  *ContextBuffersSize
  )
{
  UINTN  SpdmContextSize;

  if (ContextBuffersSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  SpdmContextSize = SpdmGetContextSize ();

  ContextBuffersSize->SpdmContextSize       = SpdmContextSize;
  ContextBuffersSize->ScratchBufferSize     = SpdmGetSizeofRequiredScratchBuffer (NULL);
  ContextBuffersSize->SendReceiveBufferSize = 0x1264; // TODO find the macro

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FreeMemoryForVmmSpdmContext (
  VMM_SPDM_CONTEXT  *Context,
  UINT32            Pages
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  FreePages (Context, Pages);

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
AllocateMemoryForVmmSpdmContext (
  VOID    **ppContext,
  UINT32  *Pages
  )
{
  VMM_SPDM_CONTEXT               *Context;
  VMM_SPDM_CONTEXT_BUFFERS_SIZE  BuffersSize = { 0 };
  UINT32                         Size;
  UINT32                         TotalPages;
  UINT8                          *Ptr;
  // PHYSICAL_ADDRESS               SpdmBaseAddress;

  // SpdmBaseAddress = (PHYSICAL_ADDRESS)FixedPcdGet32 (PcdOvmfSecScratchMemoryBase) + SIZE_4MB + SIZE_2MB;

  VmmSpmdCalculateSize (&BuffersSize);
  TotalPages  = EFI_SIZE_TO_PAGES (sizeof (VMM_SPDM_CONTEXT));
  TotalPages += EFI_SIZE_TO_PAGES (BuffersSize.SpdmContextSize);
  TotalPages += EFI_SIZE_TO_PAGES (BuffersSize.ScratchBufferSize);
  TotalPages += EFI_SIZE_TO_PAGES (BuffersSize.SendReceiveBufferSize);

  *ppContext = AllocatePages (TotalPages);
  // *ppContext = (VOID *)(UINTN)SpdmBaseAddress;
  if (*ppContext == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  *Pages  = TotalPages;
  Context = (VMM_SPDM_CONTEXT *)*ppContext;
  ZeroMem (Context, EFI_PAGES_TO_SIZE (TotalPages));

  // Context
  Ptr  = (UINT8 *)(UINTN)Context;
  Size = ALIGN_VALUE (sizeof (VMM_SPDM_CONTEXT), SIZE_4KB);

  // SpdmContext
  Ptr                 += Size;
  Context->SpdmContext = Ptr;
  Size                 = ALIGN_VALUE (BuffersSize.SpdmContextSize, SIZE_4KB);

  // ScratchBuffer
  Ptr                       += Size;
  Context->ScratchBuffer     = Ptr;
  Size                       = ALIGN_VALUE (BuffersSize.ScratchBufferSize, SIZE_4KB);
  Context->ScratchBufferSize = Size;

  // SendReceiveBuffer
  Ptr                           += Size;
  Context->SendReceiveBuffer     = Ptr;
  Size                           = ALIGN_VALUE (BuffersSize.SendReceiveBufferSize, SIZE_4KB);
  Context->SendReceiveBufferSize = Size;

  Ptr += Size;
  if (((UINTN)Ptr - (UINTN)Context) != EFI_PAGES_TO_SIZE (TotalPages)) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

/**
 * Export SecuredSpdmSessionInfo and save it in a GuidHob.
 *
 * Layout of GuidHob:
 *     EFI_HOB_GUID_TYPE + VTPM_SECURE_SESSION_INFO_TABLE + SPDM_AEAD_AES_256_GCM_KEY_IV_INFO.
 *
 * Note:
 *   This layout is same as the DTDK ACPI table.
 *
 * @param Context          The pointer to the spdm context buffer.
 *
 * @return EFI_SUCCESS     The secure session info is exported successfully
 * @return Other           Some error occurs when executing this export.
 */
STATIC
EFI_STATUS
ExportSecureSpdmSessionInfos (
  VMM_SPDM_CONTEXT  *Context
  )
{
  UINTN                           SessionKeysSize;
  VOID                            *SecureMessageContext;
  SPDM_AEAD_SESSION_KEYS          SessionKeys;
  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable;
  OVMF_WORK_AREA                  *WorkArea;

  if ((Context == NULL)
      || (Context->SessionId == 0)
      || (Context->SpdmContext == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  SecureMessageContext = SpdmGetSecuredMessageContextViaSessionId (Context->SpdmContext, Context->SessionId);
  if (SecureMessageContext == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  SessionKeysSize = sizeof (SPDM_AEAD_SESSION_KEYS);
  ZeroMem (&SessionKeys, SessionKeysSize);
  if (!SpdmSecuredMessageExportSessionKeys (SecureMessageContext, &SessionKeys, &SessionKeysSize)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((SessionKeys.AeadKeySize != AEAD_AES_256_GCM_KEY_LEN) ||
      (SessionKeys.AeadIvSize != AEAD_AES_256_GCM_IV_LEN))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Create a Guid hob to save SecuredSpdmSessionInfo
  //
  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    ASSERT (FALSE);
    return EFI_UNSUPPORTED;
  }

  ASSERT (sizeof (WorkArea->TdxWorkArea.SecTdxWorkArea.SpdmSecureSessionInfo) >= VTPM_SECURE_SESSION_INFO_TABLE_SIZE);

  InfoTable                          = (VTPM_SECURE_SESSION_INFO_TABLE *)(UINTN)WorkArea->TdxWorkArea.SecTdxWorkArea.SpdmSecureSessionInfo;
  InfoTable->SessionId               = Context->SessionId;
  InfoTable->TransportBindingVersion = VTPM_SECURE_SESSION_TRANSPORT_BINDING_VERSION;
  InfoTable->AEADAlgorithm           = AEAD_ALGORITHM_AES_256_GCM;

  CopyMem (InfoTable + 1, &SessionKeys.keys, sizeof (SPDM_AEAD_AES_256_GCM_KEY_IV_INFO));

  return EFI_SUCCESS;
}

/**
 * Disconnect from VmmSpdm responder.
*/
EFI_STATUS
EFIAPI
VmmSpdmVTpmDisconnect (
  VOID
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
VmmSpdmVTpmIsSupported (
  VOID
  )
{
  return TdQueryServiceForVtpm ();
}

VTPM_SECURE_SESSION_INFO_TABLE *
GetSpdmSecuredSessionInfo (
  VOID
  )
{
  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable;
  OVMF_WORK_AREA                  *WorkArea;

  //
  // Create a Guid hob to save SecuredSpdmSessionInfo
  //
  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    ASSERT (FALSE);
    return NULL;
  }

  InfoTable = (VTPM_SECURE_SESSION_INFO_TABLE *)(UINTN)WorkArea->TdxWorkArea.SecTdxWorkArea.SpdmSecureSessionInfo;

  return InfoTable;
}

/**
 * Check if a SecuredSpdmSession is established by finding a specific GuidHob.
 *
 * @return EFI_STATUS
 */
EFI_STATUS
EFIAPI
VmmSpdmVTpmIsConnected (
  VOID
  )
{
  // EFI_PEI_HOB_POINTERS            GuidHob;
  // UINT16                          HobLength;
  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable;

  InfoTable = GetSpdmSecuredSessionInfo ();
  if (InfoTable != NULL && InfoTable->SessionId != 0) {
    return EFI_SUCCESS;
  } else {
    return EFI_NOT_STARTED;
  }
}

/**
 * Connect to VmmSpdm responder.
 * After connection, the SecuredSpdmSession is exported and saved in a GuidHob.
 */
EFI_STATUS
EFIAPI
VmmSpdmVTpmConnect (
  VOID
  )
{
  VMM_SPDM_CONTEXT  *Context;
  UINT32            Pages;
  EFI_STATUS        Status;
  SPDM_RETURN       SpdmStatus;
  BOOLEAN           SessionSuccess;
  BOOLEAN           DestroySession;

  SessionSuccess   = FALSE;
  DestroySession   = FALSE;

  // If VMCALL_SERVICE_VTPM_GUID is not supported, VMM will not 
  // allow tdvf to send and receive VTPM messages over an spdm session.
  // Status = TdQueryServiceForVtpm ();
  // if (EFI_ERROR (Status)) {
  //   DEBUG ((DEBUG_ERROR, "TdQueryServiceForVtpm failed with %r \n", Status));
  //   return Status;
  // }

  // If RTMR[3] is non-zero, the VTPM Spdm session had already been started.
  Status = CheckRtmr3WithTdReport ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Check RTMR[3] failed with %r \n", Status));
    return Status;
  }

  Status = VmmSpdmVTpmIsConnected ();
  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  } else {
    DEBUG ((DEBUG_INFO, "vTPM-TD is connected.\n"));
  }

  Status = AllocateMemoryForVmmSpdmContext ((VOID **)&Context, &Pages);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "AllocateMemoryForVmmSpdmContext failed with %r \n", Status));
    return Status;
  }

  Status = VmmSpdmVTpmInitSpdmContext (Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "VmmSpdmVTpmInitSpdmContext failed with %r \n", Status));
    Status = EFI_ABORTED;
    goto CleanContext;
  }

  SpdmStatus = DoAuthentication (Context->SpdmContext, Context->SlotId, Context->UseMeasurementHashType);
  if (!LIBSPDM_STATUS_IS_SUCCESS (SpdmStatus)) {
    DEBUG ((DEBUG_ERROR, "DoAuthentication failed with %lx \n", SpdmStatus));
    Status = EFI_ABORTED;
    goto CleanContext;
  }

  SpdmStatus = DoStartSession (
                               Context->SpdmContext,
                               Context->UseMeasurementHashType,
                               Context->SlotId,
                               Context->SessionPolicy,
                               &Context->SessionId
                               );
  if (!LIBSPDM_STATUS_IS_SUCCESS (SpdmStatus)) {
    DEBUG ((DEBUG_ERROR, "DoStartSession failed with %lx \n", SpdmStatus));
    Status = EFI_ABORTED;
    DestroySession = TRUE;
    goto CleanContext;
  }

  Status = ExportSecureSpdmSessionInfos (Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "ExportSecureSpdmSessionInfos failed with %r \n", Status));
    Status = EFI_ABORTED;
    DestroySession = TRUE;
    goto CleanContext;
  }

  Status = CreateVtpmTdInitialEvents ();
  if (EFI_ERROR (Status)) {
    Status = EFI_ABORTED;
    DestroySession = TRUE;
  } 

CleanContext:
  if (Status == EFI_SUCCESS){
    SessionSuccess = TRUE;
  }
  
  // The first event in RTMT[3] is the VTPM Spdm session info.
  // Following a successful connection, the tdvf must extend the session information to RTMR[3]
  // and extend the hash(vTPM) to RTMR[0] RTMR[1] RTMR[2] RTMR[3].
  // Even if the session is failed to establish, the tdvf shall extend a value to RTMR[3]
  // to indicate that it tried and failed.
  Status = ExtendVtpmToAllRtmrs (SessionSuccess);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "ExtendVtpmToAllRtmrs failed with %r \n", Status));
    Status = EFI_ABORTED;
    DestroySession = TRUE;
  }

  if (DestroySession){
    Status = DoEndSession (Context);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DoEndSession failed with %r \n", Status));
      Status = EFI_ABORTED;
    }
  }

  FreeMemoryForVmmSpdmContext (Context, Pages);
  if ((SessionSuccess == FALSE) || DestroySession){
    return EFI_ABORTED;
  }

  return Status;
}

/**
 * Send/Receive data with VTpm-TD.
*/
EFI_STATUS
DoVmmSpdmSendReceive (
  UINT8                           *Request,
  UINT32                          RequestSize,
  UINT8                           *Response,
  UINTN                           *ResponseSize,
  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable
  );

/**
 * Send/Receive data with VTpm-TD.
*/
EFI_STATUS
EFIAPI
VmmSpdmVTpmSendReceive (
  UINT8   *Request,
  UINT32  RequestSize,
  UINT8   *Response,
  UINTN   *ResponseSize
  )
{
  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable;

  InfoTable = GetSpdmSecuredSessionInfo ();
  if ((InfoTable == NULL) || (InfoTable->SessionId == 0)) {
    return EFI_NOT_STARTED;
  }

  return DoVmmSpdmSendReceive (Request, RequestSize, Response, ResponseSize, InfoTable);
}

/**
 * TDVF needs the shared buffer with 4kb aligned to call the VMCALL_SERVICE
 *
 * @param SharedBuffer   The pointer of the buffer   
 * @param Pages          The number of 4 KB pages to allocate
 * 
 * @return EFI_SUCCESS   The shared buffer is allocated successfully.
 * @return Others        Some error occurs when allocated 
*/
EFI_STATUS
VtpmAllocateSharedBuffer (
  IN OUT UINT8  **SharedBuffer,
  IN UINT32     Pages
  )
{
  ASSERT (EFI_PAGES_TO_SIZE (Pages) < SIZE_2MB);
  *SharedBuffer = (UINT8 *)(UINTN)(FixedPcdGet32 (PcdOvmfSecScratchMemoryBase) + SIZE_4MB);
  return EFI_SUCCESS;
}
