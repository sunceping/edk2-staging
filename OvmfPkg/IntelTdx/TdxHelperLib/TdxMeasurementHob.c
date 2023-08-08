/** @file
  Build GuidHob for tdx measurement.

  Copyright (c) 2022 - 2023, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Library/HobLib.h>
#include <Library/PrintLib.h>
#include <Library/TcgEventLogRecordLib.h>
#include <WorkArea.h>

#ifdef TDX_PEI_LESS_BOOT
#include <Protocol/Tcg2Protocol.h>
#include <Library/BaseCryptLib.h>
#include <Library/Tpm2CommandLib.h>
#endif

#pragma pack(1)

#define HANDOFF_TABLE_DESC  "TdxTable"
typedef struct {
  UINT8                      TableDescriptionSize;
  UINT8                      TableDescription[sizeof (HANDOFF_TABLE_DESC)];
  UINT64                     NumberOfTables;
  EFI_CONFIGURATION_TABLE    TableEntry[1];
} TDX_HANDOFF_TABLE_POINTERS2;

#pragma pack()

#define FV_HANDOFF_TABLE_DESC  "Fv(XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)"
typedef PLATFORM_FIRMWARE_BLOB2_STRUCT CFV_HANDOFF_TABLE_POINTERS2;


/**
 * Build GuidHob for Tdx measurement.
 *
 * Tdx measurement includes the measurement of TdHob and CFV. They're measured
 * and extended to RTMR registers in SEC phase. Because at that moment the Hob
 * service are not available. So the values of the measurement are saved in
 * workarea and will be built into GuidHob after the Hob service is ready.
 *
 * @param RtmrIndex     RTMR index
 * @param EventType     Event type
 * @param EventData     Event data
 * @param EventSize     Size of event data
 * @param HashValue     Hash value
 * @param HashSize      Size of hash
 *
 * @retval EFI_SUCCESS  Successfully build the GuidHobs
 * @retval Others       Other error as indicated
 */
STATIC
EFI_STATUS
BuildTdxMeasurementGuidHob (
  UINT32  RtmrIndex,
  UINT32  EventType,
  UINT8   *EventData,
  UINT32  EventSize,
  UINT8   *HashValue,
  UINT32  HashSize
  )
{
  VOID                *EventHobData;
  UINT8               *Ptr;
  TPML_DIGEST_VALUES  *TdxDigest;

  if (HashSize != SHA384_DIGEST_SIZE) {
    return EFI_INVALID_PARAMETER;
  }

  #define TDX_DIGEST_VALUE_LEN  (sizeof (UINT32) + sizeof (TPMI_ALG_HASH) + SHA384_DIGEST_SIZE)

  EventHobData = BuildGuidHob (
                   &gCcEventEntryHobGuid,
                   sizeof (TCG_PCRINDEX) + sizeof (TCG_EVENTTYPE) +
                   TDX_DIGEST_VALUE_LEN +
                   sizeof (UINT32) + EventSize
                   );

  if (EventHobData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Ptr = (UINT8 *)EventHobData;

  //
  // There are 2 types of measurement registers in TDX: MRTD and RTMR[0-3].
  // According to UEFI Spec 2.10 Section 38.4.1, RTMR[0-3] is mapped to MrIndex[1-4].
  // So RtmrIndex must be increased by 1 before the event log is created.
  //
  RtmrIndex++;
  CopyMem (Ptr, &RtmrIndex, sizeof (UINT32));
  Ptr += sizeof (UINT32);

  CopyMem (Ptr, &EventType, sizeof (TCG_EVENTTYPE));
  Ptr += sizeof (TCG_EVENTTYPE);

  TdxDigest                     = (TPML_DIGEST_VALUES *)Ptr;
  TdxDigest->count              = 1;
  TdxDigest->digests[0].hashAlg = TPM_ALG_SHA384;
  CopyMem (
    TdxDigest->digests[0].digest.sha384,
    HashValue,
    SHA384_DIGEST_SIZE
    );
  Ptr += TDX_DIGEST_VALUE_LEN;

  CopyMem (Ptr, &EventSize, sizeof (UINT32));
  Ptr += sizeof (UINT32);

  CopyMem (Ptr, (VOID *)EventData, EventSize);
  Ptr += EventSize;

  return EFI_SUCCESS;
}

/**
  Get the FvName from the FV header.

  Causion: The FV is untrusted input.

  @param[in]  FvBase            Base address of FV image.
  @param[in]  FvLength          Length of FV image.

  @return FvName pointer
  @retval NULL   FvName is NOT found
**/
VOID *
GetFvName (
  IN EFI_PHYSICAL_ADDRESS  FvBase,
  IN UINT64                FvLength
  )
{
  EFI_FIRMWARE_VOLUME_HEADER      *FvHeader;
  EFI_FIRMWARE_VOLUME_EXT_HEADER  *FvExtHeader;

  if (FvBase >= MAX_ADDRESS) {
    return NULL;
  }

  if (FvLength >= MAX_ADDRESS - FvBase) {
    return NULL;
  }

  if (FvLength < sizeof (EFI_FIRMWARE_VOLUME_HEADER)) {
    return NULL;
  }

  FvHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)FvBase;
  if (FvHeader->ExtHeaderOffset < sizeof (EFI_FIRMWARE_VOLUME_HEADER)) {
    return NULL;
  }

  if (FvHeader->ExtHeaderOffset + sizeof (EFI_FIRMWARE_VOLUME_EXT_HEADER) > FvLength) {
    return NULL;
  }

  FvExtHeader = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)(UINTN)(FvBase + FvHeader->ExtHeaderOffset);

  return &FvExtHeader->FvName;
}

#ifdef TDX_PEI_LESS_BOOT
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
  
  ZeroMem(DigestList, sizeof(TPML_DIGEST_VALUES));

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
VOID *
LocalCopyDigestListToBuffer (
  IN OUT VOID            *Buffer,
  IN TPML_DIGEST_VALUES  *DigestList
  )
{
  UINTN   Index;
  UINT16  DigestSize;
  UINT32  DigestListCount;
  UINT32  *DigestListCountPtr;

  DigestListCountPtr = (UINT32 *)Buffer;
  DigestListCount    = 0;
  Buffer             = (UINT8 *)Buffer + sizeof (DigestList->count);
  for (Index = 0; Index < DigestList->count; Index++) {
    CopyMem (Buffer, &DigestList->digests[Index].hashAlg, sizeof (DigestList->digests[Index].hashAlg));
    Buffer     = (UINT8 *)Buffer + sizeof (DigestList->digests[Index].hashAlg);
    DigestSize = GetHashSizeFromAlgo (DigestList->digests[Index].hashAlg);
    CopyMem (Buffer, &DigestList->digests[Index].digest, DigestSize);
    Buffer = (UINT8 *)Buffer + DigestSize;
    DigestListCount++;
  }

  WriteUnaligned32 (DigestListCountPtr, DigestListCount);

  return Buffer;
}

STATIC
EFI_STATUS
BuildTdxMeasurementGuidHobForVtpm (
  IN UINT32  PcrIndex,
  IN UINT32  EventType,
  IN UINT8   *EventData,
  IN UINT32  EventSize,
  IN TPML_DIGEST_VALUES  *DigestList
  )
{
  VOID                *EventHobData;
  // UINT8               *Ptr;
  // TPML_DIGEST_VALUES  *TdxDigest;
  UINT32               DigestListSize = GetDigestListSize (DigestList);
  TCG_PCR_EVENT2  *TcgPcrEvent2;
  UINT8           *DigestBuffer;

  EventHobData = BuildGuidHob (
                   &gTcgEvent2EntryHobGuid,
                   sizeof (TCG_PCRINDEX) + sizeof (TCG_EVENTTYPE) +
                   DigestListSize +
                   sizeof (UINT32) + EventSize
                   );

  if (EventHobData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  TcgPcrEvent2            =  EventHobData;
  TcgPcrEvent2->PCRIndex  = PcrIndex;
  TcgPcrEvent2->EventType = EventType;
  DigestBuffer            = (UINT8 *)&TcgPcrEvent2->Digest;
  DigestBuffer            = LocalCopyDigestListToBuffer (DigestBuffer, DigestList);
  CopyMem (DigestBuffer, &EventSize, sizeof (TcgPcrEvent2->EventSize));
  DigestBuffer = DigestBuffer + sizeof (TcgPcrEvent2->EventSize);
  CopyMem (DigestBuffer, EventData, EventSize);

  return EFI_SUCCESS;


}
 #endif
/**
  Build the GuidHob for tdx measurements which were done in SEC phase.
  The measurement values are stored in WorkArea.

  @retval EFI_SUCCESS  The GuidHob is built successfully
  @retval Others       Other errors as indicated
**/
EFI_STATUS
InternalBuildGuidHobForTdxMeasurement (
  VOID
  )
{
  EFI_STATUS                   Status;
  OVMF_WORK_AREA               *WorkArea;
  // VOID                         *TdHobList;
  TDX_HANDOFF_TABLE_POINTERS2  HandoffTables;
  VOID                         *FvName;
  CFV_HANDOFF_TABLE_POINTERS2  FvBlob2;
  EFI_PHYSICAL_ADDRESS         FvBase;
  UINT64                       FvLength;
  UINT8                        *HashValue;


  if (!TdIsEnabled ()) {
    ASSERT (FALSE);
    return EFI_UNSUPPORTED;
  }

  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    return EFI_ABORTED;
  }
  EFI_PEI_HOB_POINTERS  Hob;
  VOID                  *TdHob;

  TdHob   = (VOID *)(UINTN)FixedPcdGet32 (PcdOvmfSecGhcbBase);
  Hob.Raw = (UINT8 *)TdHob;
  //
  // Walk thru the TdHob list until end of list.
  //
  while (!END_OF_HOB_LIST (Hob)) {
    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  Status = EFI_SUCCESS;

  HandoffTables.TableDescriptionSize = sizeof (HandoffTables.TableDescription);
  CopyMem (HandoffTables.TableDescription, HANDOFF_TABLE_DESC, sizeof (HandoffTables.TableDescription));
  HandoffTables.NumberOfTables = 1;
  CopyGuid (&(HandoffTables.TableEntry[0].VendorGuid), &gUefiOvmfPkgTokenSpaceGuid);
  HandoffTables.TableEntry[0].VendorTable = TdHob;

  FvBase    = (UINT64)PcdGet32 (PcdOvmfFlashNvStorageVariableBase);
  FvLength  = (UINT64)PcdGet32 (PcdCfvRawDataSize);
  FvBlob2.BlobDescriptionSize = sizeof (FvBlob2.BlobDescription);
  CopyMem (FvBlob2.BlobDescription, FV_HANDOFF_TABLE_DESC, sizeof (FvBlob2.BlobDescription));
  FvName = GetFvName (FvBase, FvLength);
  if (FvName != NULL) {
    AsciiSPrint ((CHAR8 *)FvBlob2.BlobDescription, sizeof (FvBlob2.BlobDescription), "Fv(%g)", FvName);
  }

  FvBlob2.BlobBase   = FvBase;
  FvBlob2.BlobLength = FvLength;

#ifdef TDX_PEI_LESS_BOOT
  UINT32              MeasurementType;
  UINT32              Tpm2ActivePcrBanks;
  UINTN               TdHobSize;
  TPML_DIGEST_VALUES  DigestList;

  MeasurementType = WorkArea->TdxWorkArea.SecTdxWorkArea.MeasurementType;
  Tpm2ActivePcrBanks = WorkArea->TdxWorkArea.SecTdxWorkArea.Tpm2ActivePcrBanks;

  switch (MeasurementType)
  {
  case TDX_MEASUREMENT_TYPE_NONE:
      // ASSERT (FALSE);
      DEBUG((DEBUG_INFO, "Invalid MeasurementType, would not build the Guid Hob for TdxMeasurement"));
      return EFI_INVALID_PARAMETER;
    break;
  case TDX_MEASUREMENT_TYPE_VTPM:
      TdHobSize = (UINTN)((UINT8 *)Hob.Raw - (UINT8 *)TdHob);
      if (WorkArea->TdxWorkArea.SecTdxWorkArea.TdxMeasurementsData.MeasurementsBitmap & TDX_MEASUREMENT_TDHOB_BITMASK) {
          Status = InitDigestList (Tpm2ActivePcrBanks,&DigestList, TdHob, TdHobSize);
          if (EFI_ERROR(Status))
          {
            DEBUG((DEBUG_ERROR, "%a: InitDigestList failed with %r\n", __FUNCTION__, Status));
            return Status;
          }

        Status = BuildTdxMeasurementGuidHobForVtpm (
                  0,                               // PcrIndex
                  EV_EFI_HANDOFF_TABLES2,          // EventType
                  (UINT8 *)(UINTN)&HandoffTables,  // EventData
                  sizeof (HandoffTables),          // EventSize
                  &DigestList
                  );
        if (EFI_ERROR (Status)) {
          DEBUG((DEBUG_ERROR, "%a: BuildTdxMeasurementGuidHobForVtpm failed with %r\n", __FUNCTION__, Status));
          return Status;
        }

      }
  
      if (WorkArea->TdxWorkArea.SecTdxWorkArea.TdxMeasurementsData.MeasurementsBitmap & TDX_MEASUREMENT_CFVIMG_BITMASK) {
          Status = InitDigestList (Tpm2ActivePcrBanks,&DigestList, (UINT8 *)(UINTN)FvBase, FvLength);
          if (EFI_ERROR(Status))
          {
            DEBUG((DEBUG_ERROR, "%a: InitDigestList failed with %r\n", __FUNCTION__, Status));
            return Status;
          }

        Status = BuildTdxMeasurementGuidHobForVtpm (
                  0,                              // PcrIndex
                  EV_EFI_PLATFORM_FIRMWARE_BLOB2, // EventType
                  (VOID *)&FvBlob2,               // EventData
                  sizeof (FvBlob2),               // EventSize
                  &DigestList
                  );   
      } 

      return Status;

    break;
  case TDX_MEASUREMENT_TYPE_CC:
    // Would Build with gCcEventEntryHobGuid
    break;
  default:
    DEBUG((DEBUG_ERROR, "Unknow TDX Measurement Type %x\n",MeasurementType));
    return EFI_INVALID_PARAMETER;
    break;
  }
#endif
      //
      // Build the GuidHob for TdHob measurement
      //
      if (WorkArea->TdxWorkArea.SecTdxWorkArea.TdxMeasurementsData.MeasurementsBitmap & TDX_MEASUREMENT_TDHOB_BITMASK) {
        HashValue                          = WorkArea->TdxWorkArea.SecTdxWorkArea.TdxMeasurementsData.TdHobHashValue;

        Status = BuildTdxMeasurementGuidHob (
                  0,                               // RtmrIndex
                  EV_EFI_HANDOFF_TABLES2,          // EventType
                  (UINT8 *)(UINTN)&HandoffTables,  // EventData
                  sizeof (HandoffTables),          // EventSize
                  HashValue,                       // HashValue
                  SHA384_DIGEST_SIZE               // HashSize
                  );
      }

      if (EFI_ERROR (Status)) {
        ASSERT (FALSE);
        return Status;
      }

      //
      // Build the GuidHob for Cfv measurement
      //
      if (WorkArea->TdxWorkArea.SecTdxWorkArea.TdxMeasurementsData.MeasurementsBitmap & TDX_MEASUREMENT_CFVIMG_BITMASK) {
        HashValue                   = WorkArea->TdxWorkArea.SecTdxWorkArea.TdxMeasurementsData.CfvImgHashValue;


        Status = BuildTdxMeasurementGuidHob (
                  0,                              // RtmrIndex
                  EV_EFI_PLATFORM_FIRMWARE_BLOB2, // EventType
                  (VOID *)&FvBlob2,               // EventData
                  sizeof (FvBlob2),               // EventSize
                  HashValue,                      // HashValue
                  SHA384_DIGEST_SIZE              // HashSize
                  );
      }

      if (EFI_ERROR (Status)) {
        ASSERT (FALSE);
        return Status;
      }
  
  return EFI_SUCCESS;
}
