/** @file

  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/BaseLib.h>
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
ExtendToVTpm (
  UINT32 Tpm2ActivePcrBanks,
  TDX_MEASUREMENTS_DATA *TdxMeasurementsData
  )
{
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
    // Do RTMR measurement
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
