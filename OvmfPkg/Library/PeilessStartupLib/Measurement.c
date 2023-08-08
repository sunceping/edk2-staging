/** @file

  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Protocol/DebugSupport.h>
#include <Protocol/Tcg2Protocol.h>
#include <Library/TdxHelperLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/VmmSpdmVTpmCommunicatorLib.h>
#include "PeilessStartupInternal.h"
#include "WorkArea.h"
#include <Library/HobLib.h>

/**
  Make sure that the current PCR allocations, the TPM supported PCRs,
  PcdTcg2HashAlgorithmBitmap and the PcdTpm2HashMask are all in agreement.
**/
STATIC
UINT32
SyncPcrAllocationsAndPcrMask (
  VOID
  )
{
  EFI_STATUS                       Status;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP  TpmHashAlgorithmBitmap;
  UINT32                           TpmActivePcrBanks;

  DEBUG ((DEBUG_ERROR, "SyncPcrAllocationsAndPcrMask!\n"));

  //
  // Determine the current TPM support and the Platform PCR mask.
  //
  Status = Tpm2GetCapabilitySupportedAndActivePcrs (&TpmHashAlgorithmBitmap, &TpmActivePcrBanks);
  ASSERT_EFI_ERROR (Status);

  DEBUG ((DEBUG_INFO, "Tpm2GetCapabilitySupportedAndActivePcrs - TpmHashAlgorithmBitmap: 0x%08x\n", TpmHashAlgorithmBitmap));
  DEBUG ((DEBUG_INFO, "Tpm2GetCapabilitySupportedAndActivePcrs - TpmActivePcrBanks 0x%08x\n", TpmActivePcrBanks));

  return TpmActivePcrBanks;
}

STATIC
EFI_STATUS
ExtendToRtmr (
  TDX_MEASUREMENTS_DATA *TdxMeasurementsData
  )
{
  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
InitDigestList(
  IN  UINT32 Tpm2ActivePcrBanks,
  IN  TPML_DIGEST_VALUES  *DigestList,
  IN  UINT8               *DataToHash,
  IN  UINTN               DataSize
){
  // EFI_STATUS            Status;
  UINT8               Hash256[SHA256_DIGEST_SIZE];
  UINT8               Hash384[SHA384_DIGEST_SIZE];
  UINT8               Hash512[SHA512_DIGEST_SIZE];

  if (DigestList == NULL || DataToHash == NULL)
  {
    return EFI_INVALID_PARAMETER;
  }

  if (!Sha256HashAll (DataToHash, DataSize, Hash256) ||
      !Sha384HashAll (DataToHash, DataSize, Hash384) ||
      !Sha512HashAll (DataToHash, DataSize, Hash512)) {
    return EFI_ABORTED;
  }

  DigestList->count = 0;

  if ((Tpm2ActivePcrBanks & EFI_TCG2_BOOT_HASH_ALG_SHA256) != 0) {
  DigestList->digests[DigestList->count].hashAlg = TPM_ALG_SHA256;
  CopyMem (DigestList->digests[0].digest.sha256, Hash256, SHA256_DIGEST_SIZE);
  DigestList->count++;
  }

  if ((Tpm2ActivePcrBanks & EFI_TCG2_BOOT_HASH_ALG_SHA384) != 0) {
  DigestList->digests[DigestList->count].hashAlg = TPM_ALG_SHA384;
  CopyMem (DigestList->digests[1].digest.sha384, Hash384, SHA384_DIGEST_SIZE);
  DigestList->count++;
  }

  if ((Tpm2ActivePcrBanks & EFI_TCG2_BOOT_HASH_ALG_SHA512) != 0) {
  DigestList->digests[DigestList->count].hashAlg = TPM_ALG_SHA512;
  CopyMem (DigestList->digests[2].digest.sha512, Hash512, SHA512_DIGEST_SIZE);
  DigestList->count++;
  }

  return EFI_SUCCESS;

}

STATIC
VOID
InternalDumpData (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINTN  Index;

  for (Index = 0; Index < Size; Index++) {
    DEBUG ((DEBUG_INFO, "%02x ", (UINTN)Data[Index]));
    if (Index == 15) {
      DEBUG ((DEBUG_INFO, "|"));
    }
  }
}


VOID
VTpmDumpHex (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINTN  Index;
  UINTN  Count;
  UINTN  Left;

  #define COLUME_SIZE  (16 * 2)

  Count = Size / COLUME_SIZE;
  Left  = Size % COLUME_SIZE;
  for (Index = 0; Index < Count; Index++) {
    DEBUG ((DEBUG_INFO, "%04x: ", Index * COLUME_SIZE));
    InternalDumpData (Data + Index * COLUME_SIZE, COLUME_SIZE);
    DEBUG ((DEBUG_INFO, "\n"));
  }

  if (Left != 0) {
    DEBUG ((DEBUG_INFO, "%04x: ", Index * COLUME_SIZE));
    InternalDumpData (Data + Index * COLUME_SIZE, Left);
    DEBUG ((DEBUG_INFO, "\n"));
  }
}

STATIC
EFI_STATUS
HashExtendTdHobToVtpm
 (
  UINT32 Tpm2ActivePcrBanks
 )
{

  EFI_PEI_HOB_POINTERS  Hob;
  TPML_DIGEST_VALUES  DigestList;
  EFI_STATUS Status;
  // OVMF_WORK_AREA        *WorkArea;
  VOID                  *TdHob;
  UINTN                 TdHobSize;

  TdHob   = (VOID *)(UINTN)FixedPcdGet32 (PcdOvmfSecGhcbBase);
  Hob.Raw = (UINT8 *)TdHob;

  //
  // Walk thru the TdHob list until end of list.
  //
  while (!END_OF_HOB_LIST (Hob)) {
    Hob.Raw = GET_NEXT_HOB (Hob);
  }
  ZeroMem(&DigestList,sizeof(TPML_DIGEST_VALUES));


  TdHobSize = (UINTN)((UINT8 *)Hob.Raw - (UINT8 *)TdHob);
  Status = InitDigestList(Tpm2ActivePcrBanks,&DigestList,TdHob,TdHobSize);
  if (EFI_ERROR(Status))
  {
    return Status;
  }

  VTpmDumpHex((UINT8*)&DigestList, sizeof(DigestList));

  Status = Tpm2PcrExtend(0, &DigestList);
  if (EFI_ERROR(Status))
  {
    return Status;
  }
  // ASSERT (FALSE);

  return Status;
}


STATIC
EFI_STATUS
HashExtendCfvImageToVtpm
 (
  UINT32 Tpm2ActivePcrBanks
 ){
  EFI_STATUS Status;

  // OVMF_WORK_AREA  *WorkArea;
  UINTN           CfvSize;
  UINT8           *CfvImage;
  TPML_DIGEST_VALUES  DigestList;
  CfvImage = (UINT8 *)(UINTN)PcdGet32 (PcdOvmfFlashNvStorageVariableBase);
  CfvSize = (UINT64)PcdGet32 (PcdCfvRawDataSize);

  Status = InitDigestList(Tpm2ActivePcrBanks,&DigestList,CfvImage,CfvSize);
  if (EFI_ERROR(Status))
  {
    return Status;
  }

  VTpmDumpHex((UINT8*)&DigestList, sizeof(DigestList));

  Status = Tpm2PcrExtend(0, &DigestList);
  if (EFI_ERROR(Status))
  {
            ASSERT (FALSE);
    return Status;
  }
  return Status;
 }

STATIC
EFI_STATUS
ExtendToVTpm (
  UINT32 Tpm2ActivePcrBanks,
  TDX_MEASUREMENTS_DATA *TdxMeasurementsData
  )
{
 //VTPM_TDDO only extend the hash to pcr 0
  // EFI_STATUS          Status;
  // DEBUG((DEBUG_INFO, "[Sunce] just return test \n"));
  // return EFI_SUCCESS; // debug the pcr read

  if (TdxMeasurementsData == NULL)
  {
    return EFI_INVALID_PARAMETER;
  }
  
  if (TdxMeasurementsData->MeasurementsBitmap & TDX_MEASUREMENT_TDHOB_BITMASK)
  {
    if (EFI_ERROR(HashExtendTdHobToVtpm(Tpm2ActivePcrBanks)))
    {
        ASSERT (FALSE);
      return EFI_ABORTED;
    }
  }

  if (TdxMeasurementsData->MeasurementsBitmap & TDX_MEASUREMENT_CFVIMG_BITMASK)
  {
    if (EFI_ERROR(HashExtendCfvImageToVtpm(Tpm2ActivePcrBanks)))
    {
        ASSERT (FALSE);
      return EFI_ABORTED;
    }
  }

  return EFI_SUCCESS;
}

/**
 * This function does measurement in a td-guest.
 * The measurement maybe a TPM measurement or a RTMR measurement.
 *
*/
STATIC
EFI_STATUS
DoMeasurement (
  VOID
  )
{
  EFI_STATUS      Status;
  OVMF_WORK_AREA  *WorkArea;
  UINT32          MeasurementType;
  UINT32          Tpm2ActivePcrBanks;
  TDX_MEASUREMENTS_DATA *TdxMeasurementsData;

  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  MeasurementType = WorkArea->TdxWorkArea.SecTdxWorkArea.MeasurementType;
  Tpm2ActivePcrBanks = WorkArea->TdxWorkArea.SecTdxWorkArea.Tpm2ActivePcrBanks;
  TdxMeasurementsData = &WorkArea->TdxWorkArea.SecTdxWorkArea.TdxMeasurementsData;

  if (MeasurementType == TDX_MEASUREMENT_TYPE_NONE || Tpm2ActivePcrBanks == 0) {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  Status = EFI_SUCCESS;

  if (MeasurementType == TDX_MEASUREMENT_TYPE_CC) {
    // Do RTMR measurement --- not need to do --
    Status = ExtendToRtmr (TdxMeasurementsData);
  } else if (MeasurementType == TDX_MEASUREMENT_TYPE_VTPM) {
    // Do VTPM measurement
    Status = ExtendToVTpm (Tpm2ActivePcrBanks, TdxMeasurementsData);
  } else {
    ASSERT (FALSE);
    Status = EFI_INVALID_PARAMETER;
  }

  return Status;
}

STATIC
EFI_STATUS
SetTdxMeasurementInWorkarea (
  BOOLEAN VTpmEnabled,
  UINT32 TpmActivePcrBanks
  )
{
  OVMF_WORK_AREA  *WorkArea;
  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  WorkArea->TdxWorkArea.SecTdxWorkArea.MeasurementType = VTpmEnabled ? TDX_MEASUREMENT_TYPE_VTPM : TDX_MEASUREMENT_TYPE_CC;
  WorkArea->TdxWorkArea.SecTdxWorkArea.Tpm2ActivePcrBanks = TpmActivePcrBanks;

  return EFI_SUCCESS;
}

/**
 * Do measurement in Td guest.
 * The measurement type may be vTPM or RTMR.
 */
EFI_STATUS
PeilessStartupDoMeasurement (
  VOID
  )
{
  // EFI_STATUS Status;
  BOOLEAN    VTpmEnabled;
  BOOLEAN    SharedBufferInitialized;
  UINT32     TpmActivePcrBanks;

  VTpmEnabled = FALSE;
  SharedBufferInitialized = FALSE;

  do {
    if (EFI_ERROR (TdxHelperInitSharedBuffer ())) {
      DEBUG ((DEBUG_INFO, "Init shared buffer failed.\n"));
      break;
    }
    SharedBufferInitialized = TRUE;

    if (EFI_ERROR (VmmSpdmVTpmIsSupported ())) {
      DEBUG ((DEBUG_INFO, "VTpm is not supported.\n"));
      break;
    }

    if (EFI_ERROR (VmmSpdmVTpmConnect ())) {
      DEBUG ((DEBUG_INFO, "Connect to vTPM-TD failed.\n"));
      break;
    }

    if (EFI_ERROR (Tpm2Startup (TPM_SU_CLEAR))) {
      DEBUG ((DEBUG_INFO, "Startup TPM2 failed.\n"));
      break;
    }

    TpmActivePcrBanks = SyncPcrAllocationsAndPcrMask ();
    VTpmEnabled = TRUE;

    SetTdxMeasurementInWorkarea (VTpmEnabled, TpmActivePcrBanks);
  } while (FALSE);

  DoMeasurement ();

  if (SharedBufferInitialized) {
    TdxHelperDropSharedBuffer ();
  }

  return EFI_SUCCESS;
}
