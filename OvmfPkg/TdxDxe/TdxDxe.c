/** @file

  TDX Dxe driver. This driver is dispatched early in DXE, due to being list
  in APRIORI.

  This module is responsible for:
    - Sets max logical cpus based on TDINFO
    - Sets PCI PCDs based on resource hobs
    - Alter MATD table to record address of Mailbox

  Copyright (c) 2020 - 2021, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Protocol/Cpu.h>
#include <Protocol/MpInitLibDepProtocols.h>
#include <Protocol/MemoryAccept.h>
#include <Library/UefiBootServicesTableLib.h>
#include <ConfidentialComputingGuestAttr.h>
#include <IndustryStandard/Tdx.h>
#include <Library/PlatformInitLib.h>
#include <Library/TdxLib.h>
#include <TdxAcpiTable.h>
#include <Library/MemEncryptTdxLib.h>
#include <IndustryStandard/VTpmTd.h>
#include <Protocol/Tcg2Protocol.h>
#include "WorkArea.h"

#define ALIGNED_2MB_MASK  0x1fffff
EFI_HANDLE  mTdxDxeHandle = NULL;

EFI_STATUS
EFIAPI
TdxMemoryAccept (
  IN EDKII_MEMORY_ACCEPT_PROTOCOL  *This,
  IN EFI_PHYSICAL_ADDRESS          StartAddress,
  IN UINTN                         Size
  )
{
  EFI_STATUS  Status;
  UINT32      AcceptPageSize;
  UINT64      StartAddress1;
  UINT64      StartAddress2;
  UINT64      StartAddress3;
  UINT64      Length1;
  UINT64      Length2;
  UINT64      Length3;
  UINT64      Pages;

  AcceptPageSize = FixedPcdGet32 (PcdTdxAcceptPageSize);
  StartAddress1  = 0;
  StartAddress2  = 0;
  StartAddress3  = 0;
  Length1        = 0;
  Length2        = 0;
  Length3        = 0;

  if (Size == 0) {
    return EFI_SUCCESS;
  }

  if (ALIGN_VALUE (StartAddress, SIZE_2MB) != StartAddress) {
    StartAddress1 = StartAddress;
    Length1       = ALIGN_VALUE (StartAddress, SIZE_2MB) - StartAddress;
    if (Length1 >= Size) {
      Length1 = Size;
    }

    StartAddress += Length1;
    Size         -= Length1;
  }

  if (Size > SIZE_2MB) {
    StartAddress2 = StartAddress;
    Length2       = Size & ~(UINT64)ALIGNED_2MB_MASK;
    StartAddress += Length2;
    Size         -= Length2;
  }

  if (Size) {
    StartAddress3 = StartAddress;
    Length3       = Size;
  }

  Status = EFI_SUCCESS;
  if (Length1 > 0) {
    Pages  = Length1 / SIZE_4KB;
    Status = TdAcceptPages (StartAddress1, Pages, SIZE_4KB);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  if (Length2 > 0) {
    Pages  = Length2 / AcceptPageSize;
    Status = TdAcceptPages (StartAddress2, Pages, AcceptPageSize);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  if (Length3 > 0) {
    Pages  = Length3 / SIZE_4KB;
    Status = TdAcceptPages (StartAddress3, Pages, SIZE_4KB);
    ASSERT (!EFI_ERROR (Status));
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return Status;
}

EDKII_MEMORY_ACCEPT_PROTOCOL  mMemoryAcceptProtocol = {
  TdxMemoryAccept
};

VOID
SetPcdSettings (
  EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  )
{
  RETURN_STATUS  PcdStatus;

  PcdStatus = PcdSet64S (PcdConfidentialComputingGuestAttr, PlatformInfoHob->PcdConfidentialComputingGuestAttr);
  ASSERT_RETURN_ERROR (PcdStatus);
  PcdStatus = PcdSetBoolS (PcdSetNxForStack, PlatformInfoHob->PcdSetNxForStack);
  ASSERT_RETURN_ERROR (PcdStatus);

  DEBUG ((
    DEBUG_INFO,
    "HostBridgeDevId=0x%x, CCAttr=0x%x, SetNxForStack=%x\n",
    PlatformInfoHob->HostBridgeDevId,
    PlatformInfoHob->PcdConfidentialComputingGuestAttr,
    PlatformInfoHob->PcdSetNxForStack
    ));

  PcdStatus = PcdSet32S (PcdCpuBootLogicalProcessorNumber, PlatformInfoHob->PcdCpuBootLogicalProcessorNumber);
  ASSERT_RETURN_ERROR (PcdStatus);
  PcdStatus = PcdSet32S (PcdCpuMaxLogicalProcessorNumber, PlatformInfoHob->PcdCpuMaxLogicalProcessorNumber);
  ASSERT_RETURN_ERROR (PcdStatus);

  DEBUG ((
    DEBUG_INFO,
    "MaxCpuCount=0x%x, BootCpuCount=0x%x\n",
    PlatformInfoHob->PcdCpuMaxLogicalProcessorNumber,
    PlatformInfoHob->PcdCpuBootLogicalProcessorNumber
    ));

  PcdSet64S (PcdEmuVariableNvStoreReserved, PlatformInfoHob->PcdEmuVariableNvStoreReserved);

  if (TdIsEnabled ()) {
    PcdStatus = PcdSet64S (PcdTdxSharedBitMask, TdSharedPageMask ());
    ASSERT_RETURN_ERROR (PcdStatus);
    DEBUG ((DEBUG_INFO, "TdxSharedBitMask=0x%llx\n", PcdGet64 (PcdTdxSharedBitMask)));
  }

  PcdStatus = PcdSet64S (PcdPciMmio64Base, PlatformInfoHob->PcdPciMmio64Base);
  ASSERT_RETURN_ERROR (PcdStatus);
  PcdStatus = PcdSet64S (PcdPciMmio64Size, PlatformInfoHob->PcdPciMmio64Size);
  ASSERT_RETURN_ERROR (PcdStatus);
  PcdStatus = PcdSet64S (PcdPciMmio32Base, PlatformInfoHob->PcdPciMmio32Base);
  ASSERT_RETURN_ERROR (PcdStatus);
  PcdStatus = PcdSet64S (PcdPciMmio32Size, PlatformInfoHob->PcdPciMmio32Size);
  ASSERT_RETURN_ERROR (PcdStatus);
  PcdStatus = PcdSet64S (PcdPciIoBase, PlatformInfoHob->PcdPciIoBase);
  ASSERT_RETURN_ERROR (PcdStatus);
  PcdStatus = PcdSet64S (PcdPciIoSize, PlatformInfoHob->PcdPciIoSize);
  ASSERT_RETURN_ERROR (PcdStatus);
}

/**
  Location of resource hob matching type and starting address

  @param[in]  Type             The type of resource hob to locate.

  @param[in]  Start            The resource hob must at least begin at address.

  @retval pointer to resource  Return pointer to a resource hob that matches or NULL.
**/
STATIC
EFI_HOB_RESOURCE_DESCRIPTOR *
GetResourceDescriptor (
  EFI_RESOURCE_TYPE     Type,
  EFI_PHYSICAL_ADDRESS  Start,
  EFI_PHYSICAL_ADDRESS  End
  )
{
  EFI_PEI_HOB_POINTERS         Hob;
  EFI_HOB_RESOURCE_DESCRIPTOR  *ResourceDescriptor = NULL;

  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    DEBUG ((
      DEBUG_INFO,
      "%a:%d: resource type 0x%x %llx %llx\n",
      __func__,
      __LINE__,
      Hob.ResourceDescriptor->ResourceType,
      Hob.ResourceDescriptor->PhysicalStart,
      Hob.ResourceDescriptor->ResourceLength
      ));

    if ((Hob.ResourceDescriptor->ResourceType == Type) &&
        (Hob.ResourceDescriptor->PhysicalStart >= Start) &&
        ((Hob.ResourceDescriptor->PhysicalStart + Hob.ResourceDescriptor->ResourceLength) < End))
    {
      ResourceDescriptor = Hob.ResourceDescriptor;
      break;
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  return ResourceDescriptor;
}

/**
  Location of resource hob matching type and highest address below end

  @param[in]  Type             The type of resource hob to locate.

  @param[in]  End              The resource hob return is the closest to the End address

  @retval pointer to resource  Return pointer to a resource hob that matches or NULL.
**/
STATIC
EFI_HOB_RESOURCE_DESCRIPTOR *
GetHighestResourceDescriptor (
  EFI_RESOURCE_TYPE     Type,
  EFI_PHYSICAL_ADDRESS  End
  )
{
  EFI_PEI_HOB_POINTERS         Hob;
  EFI_HOB_RESOURCE_DESCRIPTOR  *ResourceDescriptor = NULL;

  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    if ((Hob.ResourceDescriptor->ResourceType == Type) &&
        (Hob.ResourceDescriptor->PhysicalStart < End))
    {
      if (!ResourceDescriptor ||
          (ResourceDescriptor->PhysicalStart < Hob.ResourceDescriptor->PhysicalStart))
      {
        ResourceDescriptor = Hob.ResourceDescriptor;
      }
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  return ResourceDescriptor;
}

/**
  Set the shared bit for mmio region in Tdx guest.

  In Tdx guest there are 2 ways to access mmio, TdVmcall or direct access.
  For direct access, the shared bit of the PageTableEntry should be set.
  The mmio region information is retrieved from hob list.

  @retval EFI_SUCCESS                 The shared bit is set successfully.
  @retval EFI_UNSUPPORTED             Setting the shared bit of memory region
                                      is not supported
**/
EFI_STATUS
SetMmioSharedBit (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  Hob.Raw = (UINT8 *)GetHobList ();

  //
  // Parse the HOB list until end of list or matching type is found.
  //
  while (!END_OF_HOB_LIST (Hob)) {
    if (  (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR)
       && (Hob.ResourceDescriptor->ResourceType == EFI_RESOURCE_MEMORY_MAPPED_IO))
    {
      MemEncryptTdxSetPageSharedBit (
        0,
        Hob.ResourceDescriptor->PhysicalStart,
        EFI_SIZE_TO_PAGES (Hob.ResourceDescriptor->ResourceLength)
        );
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  return EFI_SUCCESS;
}

#ifdef VTPM_FEATURE_ENABLED
STATIC
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
  }

  InfoTable = (VTPM_SECURE_SESSION_INFO_TABLE *)(UINTN)WorkArea->TdxWorkArea.SecTdxWorkArea.SpdmSecureSessionInfo;

  return InfoTable;
}


EFI_STATUS
EFIAPI
VtpmDetect(
 IN  EDKII_VTPM_BASED_MEASUREMENT_PROTOCOL  *This
 )
{
  OVMF_WORK_AREA   *WorkArea;

  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    DEBUG((DEBUG_ERROR, "WorkArea should never be NULL\n"));
    CpuDeadLoop();
  }

  if (WorkArea->TdxWorkArea.SecTdxWorkArea.MeasurementType != TDX_MEASUREMENT_TYPE_VTPM)
  {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}

EDKII_VTPM_BASED_MEASUREMENT_PROTOCOL mVtpmBasedMeasurementProtocol = {
 VtpmDetect
};

STATIC
VOID
InstallVtpmBasedMeasurement (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEdkiiVtpmBasedMeasurementProtocolGuid,
                  &mVtpmBasedMeasurementProtocol,
                  NULL
                  );
  if (EFI_ERROR(Status)){
    DEBUG ((DEBUG_ERROR, "InstallMultipleProtocolInterfaces is failed with %r\n", Status));
    ASSERT(FALSE);
    return;
  }

  DEBUG ((DEBUG_INFO, "InstallVtpmBasedMeasurementProtocol is %r\n", Status));

}

STATIC
EFI_STATUS
PrepareForVtpm (
  VOID
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Address;
  VOID                  *Registration;
  UINTN                 Size;
  EFI_EVENT             AcpiTableEvent;
  VTPM_SECURE_SESSION_INFO_TABLE *InfoTable;
  OVMF_WORK_AREA  *WorkArea;

  DEBUG ((DEBUG_INFO, ">>%a\n", __FUNCTION__));

  InstallVtpmBasedMeasurement();

  // Check if SecuredSpdmSession is established
  InfoTable = GetSpdmSecuredSessionInfo ();
  if (InfoTable == NULL || InfoTable->SessionId == 0) {
    DEBUG ((DEBUG_INFO, "SecuredSpdmSession is not established.\n"));
    return EFI_NOT_STARTED;
  }

  WorkArea = (OVMF_WORK_AREA *)FixedPcdGet32 (PcdOvmfWorkAreaBase);
  if (WorkArea == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  UINT32 MeasurementType = WorkArea->TdxWorkArea.SecTdxWorkArea.MeasurementType;
  UINT32 Tpm2ActivePcrBanks = WorkArea->TdxWorkArea.SecTdxWorkArea.Tpm2ActivePcrBanks;

  if (MeasurementType == TDX_MEASUREMENT_TYPE_VTPM && Tpm2ActivePcrBanks != 0)
  {
    // Set PcdTpmInstanceGuid
    Size   = sizeof (gEfiTpmDeviceInstanceTpm20DtpmGuid);
    Status = PcdSetPtrS (
                PcdTpmInstanceGuid,
                &Size,
                &gEfiTpmDeviceInstanceTpm20DtpmGuid
                );
    ASSERT_EFI_ERROR (Status);

    // Set active pcr banks
    PcdSet32S (PcdTpm2HashMask, WorkArea->TdxWorkArea.SecTdxWorkArea.Tpm2ActivePcrBanks);
  }

  Status = gBS->AllocatePages (
                               AllocateAnyPages,
                               EfiACPIMemoryNVS,
                               1,
                               &Address
                               );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ZeroMem ((VOID *)(UINTN)Address, EFI_PAGES_TO_SIZE (1));
  CopyMem ((VOID *)(UINTN)Address, InfoTable, VTPM_SECURE_SESSION_INFO_TABLE_SIZE);

  PcdSet64S (PcdVtpmSecureSessionInfoTableAddr, Address);
  PcdSet64S (PcdVtpmSecureSessionInfoTableSize, EFI_PAGES_TO_SIZE (1));

  //
  // If VTPM is enabled then create event callback to install TDTK ACPI Table
  //
  Status = gBS->CreateEventEx (
                               EVT_NOTIFY_SIGNAL,
                               TPL_CALLBACK,
                               InstallTdtkAcpiTable,
                               NULL,
                               &gEfiAcpiTableProtocolGuid,
                               &AcpiTableEvent
                               );
  ASSERT (!EFI_ERROR (Status));

  Status = gBS->RegisterProtocolNotify (
                                        &gEfiAcpiTableProtocolGuid,
                                        AcpiTableEvent,
                                        &Registration
                                        );
  ASSERT (!EFI_ERROR (Status));

  return EFI_SUCCESS;
}
#endif

EFI_STATUS
EFIAPI
TdxDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                   Status;
  RETURN_STATUS                PcdStatus;
  EFI_HOB_RESOURCE_DESCRIPTOR  *Res          = NULL;
  EFI_HOB_RESOURCE_DESCRIPTOR  *MemRes       = NULL;
  EFI_HOB_PLATFORM_INFO        *PlatformInfo = NULL;
  EFI_HOB_GUID_TYPE            *GuidHob;
  UINT32                       CpuMaxLogicalProcessorNumber;
  TD_RETURN_DATA               TdReturnData;
  EFI_EVENT                    QemuAcpiTableEvent;
  void                         *Registration;

  GuidHob = GetFirstGuidHob (&gUefiOvmfPkgPlatformInfoGuid);

  if (GuidHob == NULL) {
    return EFI_UNSUPPORTED;
  }

  //
  // Both Td and Non-Td guest have PlatformInfoHob which contains the HostBridgePciDevId
  //
  PlatformInfo = (EFI_HOB_PLATFORM_INFO *)GET_GUID_HOB_DATA (GuidHob);
  ASSERT (PlatformInfo->HostBridgeDevId != 0);
  PcdStatus = PcdSet16S (PcdOvmfHostBridgePciDevId, PlatformInfo->HostBridgeDevId);
  ASSERT_RETURN_ERROR (PcdStatus);

 #ifdef TDX_PEI_LESS_BOOT
  //
  // For Pei-less boot, PlatformInfo contains more information and
  // need to set PCDs based on these information.
  //
  SetPcdSettings (PlatformInfo);
 #endif

  if (!TdIsEnabled ()) {
    //
    // If it is Non-Td guest, we install gEfiMpInitLibMpDepProtocolGuid so that
    // MpInitLib will be used in CpuDxe driver.
    //
    gBS->InstallProtocolInterface (
           &ImageHandle,
           &gEfiMpInitLibMpDepProtocolGuid,
           EFI_NATIVE_INTERFACE,
           NULL
           );

    return EFI_SUCCESS;
  }

  SetMmioSharedBit ();

  //
  // It is Td guest, we install gEfiMpInitLibUpDepProtocolGuid so that
  // MpInitLibUp will be used in CpuDxe driver.
  //
  gBS->InstallProtocolInterface (
         &ImageHandle,
         &gEfiMpInitLibUpDepProtocolGuid,
         EFI_NATIVE_INTERFACE,
         NULL
         );

  //
  // Install MemoryAccept protocol for TDX
  //
  Status = gBS->InstallProtocolInterface (
                  &mTdxDxeHandle,
                  &gEdkiiMemoryAcceptProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMemoryAcceptProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Install EdkiiMemoryAcceptProtocol failed.\n"));
  }

  //
  // Call TDINFO to get actual number of cpus in domain
  //
  Status = TdCall (TDCALL_TDINFO, 0, 0, 0, &TdReturnData);
  ASSERT (Status == EFI_SUCCESS);

  CpuMaxLogicalProcessorNumber = PcdGet32 (PcdCpuMaxLogicalProcessorNumber);

  //
  // Adjust PcdCpuMaxLogicalProcessorNumber, if needed. If firmware is configured for
  // more than number of reported cpus, update.
  //
  if (CpuMaxLogicalProcessorNumber > TdReturnData.TdInfo.NumVcpus) {
    PcdStatus = PcdSet32S (PcdCpuMaxLogicalProcessorNumber, TdReturnData.TdInfo.NumVcpus);
    ASSERT_RETURN_ERROR (PcdStatus);
  }

  //
  // Register for protocol notifications to call the AlterAcpiTable(),
  // the protocol will be installed in AcpiPlatformDxe when the ACPI
  // table provided by Qemu is ready.
  //
  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  AlterAcpiTable,
                  NULL,
                  &QemuAcpiTableEvent
                  );

  Status = gBS->RegisterProtocolNotify (
                  &gQemuAcpiTableNotifyProtocolGuid,
                  QemuAcpiTableEvent,
                  &Registration
                  );
 #ifdef VTPM_FEATURE_ENABLED
  PrepareForVtpm ();
 #endif

  #define INIT_PCDSET(NAME, RES)  do {\
  PcdStatus = PcdSet64S (NAME##Base, (RES)->PhysicalStart); \
  ASSERT_RETURN_ERROR (PcdStatus); \
  PcdStatus = PcdSet64S (NAME##Size, (RES)->ResourceLength); \
  ASSERT_RETURN_ERROR (PcdStatus); \
} while(0)

  if (PlatformInfo) {
    PcdSet16S (PcdOvmfHostBridgePciDevId, PlatformInfo->HostBridgeDevId);

    if ((Res = GetResourceDescriptor (EFI_RESOURCE_MEMORY_MAPPED_IO, (EFI_PHYSICAL_ADDRESS)0x100000000, (EFI_PHYSICAL_ADDRESS)-1)) != NULL) {
      INIT_PCDSET (PcdPciMmio64, Res);
    }

    if ((Res = GetResourceDescriptor (EFI_RESOURCE_IO, 0, 0x10001)) != NULL) {
      INIT_PCDSET (PcdPciIo, Res);
    }

    //
    // To find low mmio, first find top of low memory, and then search for io space.
    //
    if ((MemRes = GetHighestResourceDescriptor (EFI_RESOURCE_SYSTEM_MEMORY, 0xffc00000)) != NULL) {
      if ((Res = GetResourceDescriptor (EFI_RESOURCE_MEMORY_MAPPED_IO, MemRes->PhysicalStart, 0x100000000)) != NULL) {
        INIT_PCDSET (PcdPciMmio32, Res);
      }
    }
  }

  return EFI_SUCCESS;
}
