/** @file

  Copyright (c) 2022 - 2023, Intel Corporation. All rights reserved. <BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <PiDxe.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PcdLib.h>
#include "VTpmTransport.h"
#include "VmmSpdmInternal.h"

EFI_STATUS
VTpmCommEncodeMessage (
  IN UINTN                               InputMessageSize,
  IN UINT8                               *InputMessage,
  IN OUT UINTN                           *TransportMessageSize,
  IN OUT UINT8                           *TransportMessage,
  IN OUT VTPM_SECURE_SESSION_INFO_TABLE  *SecureSessionInfoTable
  );

EFI_STATUS
VTpmCommDecodeMessage (
  IN UINTN                               TransportMessageSize,
  IN UINT8                               *TransportMessage,
  IN OUT UINTN                           *MessageSize,
  IN OUT UINT8                           *Message,
  IN OUT VTPM_SECURE_SESSION_INFO_TABLE  *SecureSessionInfoTable
  );

EFI_STATUS
VTpmContextWrite (
  IN UINTN       RequestSize,
  IN CONST VOID  *Request,
  IN UINT64      Timeout
  );

/**
  ReadBuffer from vTPM-TD
**/
EFI_STATUS
VTpmContextRead (
  IN OUT UINTN  *ResponseSize,
  IN OUT VOID   *Response,
  IN UINT64     Timeout
  );

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
  )
{
  #define VTPM_DEFAULT_MAX_BUFFER_SIZE  0x1000
  EFI_STATUS  Status;
  UINT8       TransportMessage[VTPM_DEFAULT_MAX_BUFFER_SIZE];
  UINTN       TransportMessageSize = VTPM_DEFAULT_MAX_BUFFER_SIZE;
  UINT8       Message[VTPM_DEFAULT_MAX_BUFFER_SIZE];
  UINTN       MessageSize = VTPM_DEFAULT_MAX_BUFFER_SIZE;

  Status = VTpmCommEncodeMessage (RequestSize, Request, &TransportMessageSize, TransportMessage, InfoTable);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to encode message.\n"));
    return Status;
  }

  if (TransportMessageSize > VTPM_DEFAULT_MAX_BUFFER_SIZE) {
    DEBUG((DEBUG_ERROR,"TransportMessageSize %x is out of max buffer size \n",TransportMessageSize));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = VTpmContextWrite (TransportMessageSize, TransportMessage, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  TransportMessageSize = VTPM_DEFAULT_MAX_BUFFER_SIZE;
  ZeroMem (TransportMessage, sizeof (TransportMessage));
  Status = VTpmContextRead (&TransportMessageSize, TransportMessage, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ZeroMem (Message, MessageSize);
  Status = VTpmCommDecodeMessage (TransportMessageSize, TransportMessage, &MessageSize, Message, InfoTable);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  CopyMem (Response, Message, MessageSize);
  *ResponseSize = MessageSize;

  return EFI_SUCCESS;
}


/**
 * Calculate the buffers' size of a VmmSpdmContext.
 */
UINTN
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

  VmmSpmdCalculateSize (&BuffersSize);
  TotalPages  = EFI_SIZE_TO_PAGES (sizeof (VMM_SPDM_CONTEXT));
  TotalPages += EFI_SIZE_TO_PAGES (BuffersSize.SpdmContextSize);
  TotalPages += EFI_SIZE_TO_PAGES (BuffersSize.ScratchBufferSize);
  TotalPages += EFI_SIZE_TO_PAGES (BuffersSize.SendReceiveBufferSize);

  *ppContext = AllocatePages (TotalPages);
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
 * Export SecuredSpdmSessionInfo and save it in WorkArea.
 *
 * @param Context          The pointer to the spdm context buffer.
 *
 * @return EFI_SUCCESS     The secure session info is exported successfully
 * @return Other           Some error occurs when executing this export.
 */
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
