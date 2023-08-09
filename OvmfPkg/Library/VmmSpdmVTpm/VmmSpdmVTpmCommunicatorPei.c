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
#include <Library/UefiBootServicesTableLib.h>
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
#include "WorkArea.h"

/**
 * Disconnect from VmmSpdm responder.
*/
EFI_STATUS
EFIAPI
VmmSpdmVTpmDisconnect (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}


STATIC
VOID
SetTdxMeasurementTypeInWorkare (
 BOOLEAN VTpmEnabled
 )
{
  OVMF_WORK_AREA  *WorkArea;
  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    CpuDeadLoop(); 
  }

  WorkArea->TdxWorkArea.SecTdxWorkArea.MeasurementType = VTpmEnabled ? TDX_MEASUREMENT_TYPE_VTPM : TDX_MEASUREMENT_TYPE_CC;

}

EFI_STATUS
EFIAPI
VmmSpdmVTpmIsSupported (
  VOID
  )
{
  EFI_STATUS        Status;
  BOOLEAN           VTpmEnabled;

  VTpmEnabled = FALSE;

  // If VMCALL_SERVICE_VTPM_GUID is not supported, VMM will not 
  // allow tdvf to send and receive VTPM messages over an spdm session.
  Status = TdQueryServiceForVtpm ();
  if (!EFI_ERROR (Status)) {
    VTpmEnabled = TRUE;
  }

  SetTdxMeasurementTypeInWorkare(VTpmEnabled);

  return Status ;
}

/**
 * Check if a SecuredSpdmSession is established by WorkArea.
 *
 * @return EFI_STATUS
 */
EFI_STATUS
EFIAPI
VmmSpdmVTpmIsConnected (
  VOID
  )
{

  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable;

  // SPDM_AEAD_AES_256_GCM_KEY_IV_INFO *KeyIvInfo;

  InfoTable = GetSpdmSecuredSessionInfo ();
  if (InfoTable == NULL || InfoTable->SessionId == 0) {
    return EFI_NOT_STARTED;
  }

  // TODO
  // Check other information in KeyIvInfo

  return EFI_SUCCESS;
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
  // return VmmSpdmVTpmIsConnected ();
  VMM_SPDM_CONTEXT  *Context;
  UINT32            Pages;
  EFI_STATUS        Status;
  SPDM_RETURN       SpdmStatus;
  BOOLEAN           SessionSuccess;
  BOOLEAN           DestroySession;

  SessionSuccess   = FALSE;
  DestroySession   = FALSE;

  Status = VmmSpdmVTpmIsSupported ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "VmmSpdmVTpmIsSupported failed with %r \n", Status));
    return Status;
  }

  // If RTMR[3] is non-zero, the VTPM Spdm session had already been started.
  Status = CheckRtmr3WithTdReport ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Check RTMR[3] failed with %r \n", Status));
    return Status;
  }

  Status = VmmSpdmVTpmIsConnected ();
  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
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

VTPM_SECURE_SESSION_INFO_TABLE *
GetSpdmSecuredSessionInfo (
  VOID
  )
{

  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable;
  OVMF_WORK_AREA                  *WorkArea;

  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    ASSERT (FALSE);
    return NULL;
  }

  InfoTable = (VTPM_SECURE_SESSION_INFO_TABLE *)(UINTN)WorkArea->TdxWorkArea.SecTdxWorkArea.SpdmSecureSessionInfo;

  return InfoTable;
}

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
  EFI_STATUS                      Status; 
  VTPM_SECURE_SESSION_INFO_TABLE  *InfoTable;

  InfoTable = GetSpdmSecuredSessionInfo ();
  if ((InfoTable == NULL) || (InfoTable->SessionId == 0)) {
    return EFI_NOT_STARTED;
  }

  Status = DoVmmSpdmSendReceive (Request, RequestSize, Response, ResponseSize, InfoTable);
  if (EFI_ERROR(Status)){
    DEBUG((DEBUG_ERROR, "DoVmmSpdmSendReceive failed with %r\n", Status));
    //Destroy the session after send-receive failed
    InfoTable->SessionId = 0;
  }

  return Status;
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
  EFI_STATUS  Status;
  UINT8       *Buffer;
  UINTN       DataLength;
  VOID        *GuidHobRawData;

  EFI_PEI_HOB_POINTERS  GuidHob;
  UINT16                HobLength;

  VTPM_SHARED_BUFFER_INFO_STRUCT  *VtpmSharedBufferInfo;

  GuidHob.Guid = GetFirstGuidHob (&gEdkiiVTpmSharedBufferInfoHobGuid);
  DEBUG ((DEBUG_INFO, "%a: GuidHob.Guid %p \n", __FUNCTION__ , GuidHob.Guid));
  if (GuidHob.Guid == NULL) {
    Buffer = (UINT8 *)AllocatePages (Pages);
    if (Buffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Status = MemEncryptTdxSetPageSharedBit (0, (PHYSICAL_ADDRESS)Buffer, Pages);
    if (EFI_ERROR (Status)) {
      FreePages (Buffer, Pages);
      return EFI_OUT_OF_RESOURCES;
    }

    //
    // Create a Guid hob to save the VtpmSharedBufferInfoStruct
    //
    DataLength = sizeof (VTPM_SHARED_BUFFER_INFO_STRUCT);

    GuidHobRawData = BuildGuidHob (
                                   &gEdkiiVTpmSharedBufferInfoHobGuid,
                                   DataLength
                                   );

    if (GuidHobRawData == NULL) {
      DEBUG ((DEBUG_ERROR, "%a : BuildGuidHob failed \n", __FUNCTION__));
      return EFI_OUT_OF_RESOURCES;
    }

    VtpmSharedBufferInfo                = GuidHobRawData;
    VtpmSharedBufferInfo->BufferAddress = (UINT64)Buffer;
    VtpmSharedBufferInfo->BufferSize    = (UINT64)EFI_PAGES_TO_SIZE (Pages);  

    *SharedBuffer = Buffer;
    return EFI_SUCCESS;
  }

  HobLength = sizeof (EFI_HOB_GUID_TYPE) + sizeof (VTPM_SHARED_BUFFER_INFO_STRUCT);
  if (GuidHob.Guid->Header.HobLength != HobLength) {
    DEBUG ((DEBUG_ERROR, "%a: The GuidHob.Guid->Header.HobLength is not equal HobLength, %x vs %x \n", __FUNCTION__, GuidHob.Guid->Header.HobLength, HobLength));
    return EFI_INVALID_PARAMETER;
  }

  VtpmSharedBufferInfo = (VTPM_SHARED_BUFFER_INFO_STRUCT *)(GuidHob.Guid + 1);

  *SharedBuffer = (UINT8 *)(UINTN)(VtpmSharedBufferInfo->BufferAddress);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
VmmSpdmVTpmClearSharedBit (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT8       *Buffer;
  UINT32       Pages;

  EFI_PEI_HOB_POINTERS  GuidHob;
  UINT16                HobLength;

  VTPM_SHARED_BUFFER_INFO_STRUCT  *VtpmSharedBufferInfo;

  Buffer = NULL;
  VtpmSharedBufferInfo= NULL;

  GuidHob.Guid = GetFirstGuidHob (&gEdkiiVTpmSharedBufferInfoHobGuid);
  DEBUG ((DEBUG_INFO, "%a: GuidHob.Guid %p \n", __FUNCTION__ , GuidHob.Guid));
  if (GuidHob.Guid == NULL) {
    return EFI_SUCCESS;
  }

  HobLength = sizeof (EFI_HOB_GUID_TYPE) + sizeof (VTPM_SHARED_BUFFER_INFO_STRUCT);
  if (GuidHob.Guid->Header.HobLength != HobLength) {
    DEBUG ((DEBUG_ERROR, "%a: The GuidHob.Guid->Header.HobLength is not equal HobLength, %x vs %x \n", __FUNCTION__, GuidHob.Guid->Header.HobLength, HobLength));
    return EFI_OUT_OF_RESOURCES;
  }

  VtpmSharedBufferInfo = (VTPM_SHARED_BUFFER_INFO_STRUCT *)(GuidHob.Guid + 1);

  Buffer = (UINT8 *)(UINTN)(VtpmSharedBufferInfo->BufferAddress);
  Pages  = EFI_SIZE_TO_PAGES(VtpmSharedBufferInfo->BufferSize);
  Status = MemEncryptTdxClearPageSharedBit (0, (PHYSICAL_ADDRESS)Buffer, Pages);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "%a: MemEncryptTdxClearPageSharedBit failed with %r \n", __FUNCTION__ , Status));
  }

  return Status;

}
