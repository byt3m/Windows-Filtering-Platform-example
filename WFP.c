#include "WFP.h"

void create(char* processPath)
{
    DWORD result = 0;
    HANDLE hEngine = NULL;
    FWPM_PROVIDER0 provider = { 0 };
    FWPM_FILTER_CONDITION0 cond = { 0 };
    FWPM_FILTER0 filter = { 0 };
    FWP_BYTE_BLOB* appId = NULL;
    WCHAR wProcessPath[MAX_PATH] = { 0 };
    UINT64 filterId = 0;

    // Get engine handle
    printf("[i] Getting WFP engine handle\n");
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS)
    {
        printf("[X] FwpmEngineOpen0 failed with code 0x%x.\n", result);
        return;
    }

    // Create provider
    printf("[i] Creating provider\n");
    provider.providerKey = providerKey;
    provider.displayData.name = providerName;
    provider.displayData.description = providerDescription;
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    result = FwpmProviderAdd0(hEngine, &provider, NULL);
    if (result == 0x80320009) // 0x80320009 equals to provider already existing
    {
        printf("  [i] Provider already exists\n");
    }
    else if (result != ERROR_SUCCESS)
    {
        printf("  [X] FwpmProviderAdd0 failed with code 0x%x.\n", result);
        return;
    }

    // Get AppID aka NTFS path
    printf("[i] Getting process \"%s\" app ID\n", processPath);
    result = MultiByteToWideChar(CP_UTF8, 0, processPath, -1, wProcessPath, MAX_PATH);
    if (result == 0)
    {
        printf("  [X] MultiByteToWideChar failed with error code: 0x%x.\n", GetLastError());
        return;
    }
    result = FwpmGetAppIdFromFileName0(wProcessPath, &appId);
    if (result != ERROR_SUCCESS)
    {
        printf("[X] FwpmGetAppIdFromFileName0 failed with code 0x%x.\n", result);
        return;
    }

    // Add filter to both IPv4 and IPv6 layers
    printf("[i] Creating filters\n");
    filter.displayData.name = filterName;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;
    filter.filterCondition = &cond;
    filter.numFilterConditions = 1;
    
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) 
    {
        printf("  [*] Added WFP filter for \"%s\" (Filter id: 0x%x%x, IPv4 layer).\n", processPath, (UINT32)(filterId >> 32), (UINT32)(filterId & 0xFFFFFFFF));
    }
    else 
    {
        printf("  [X] Failed to add filter in IPv4 layer with error code: 0x%x.\n", result);
    }

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) 
    {
        printf("  [*] Added WFP filter for \"%s\" (Filter id: 0x%x%x, IPv6 layer).\n", processPath, (UINT32)(filterId >> 32), (UINT32)(filterId & 0xFFFFFFFF));
    }
    else 
    {
        printf("  [X] Failed to add filter in IPv6 layer with error code: 0x%x.\n", result);
    }

    FwpmEngineClose0(hEngine);
    return;
}

void clean()
{
    DWORD result = 0;
    HANDLE hEngine = NULL;
    FWPM_PROVIDER0 provider = { 0 };
    HANDLE hFilterEnum = NULL;
    FWPM_FILTER0** filters = NULL;
    UINT32 numFilters = 0;
    BOOL foundFilter = FALSE;

    // Get engine handle
    printf("[i] Getting WFP engine handle\n");
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS)
    {
        printf("  [X] FwpmEngineOpen0 failed with code 0x%x.\n", result);
        return;
    }

    // Read provider
    printf("[i] Reading provider\n");
    result = FwpmProviderGetByKey0(hEngine, &providerKey, &provider);
    if (result == 0x80320008)
    {
        printf("  [X] Provider not found\n");
        return;
    }
    else if (result != ERROR_SUCCESS)
    {
        printf("  [X] FwpmProviderGetByKey0 failed with code 0x%x.\n", result);
        return;
    }

    // Open filter enum handle
    printf("[i] Opening filter enum handle\n");
    result = FwpmFilterCreateEnumHandle0(hEngine, NULL, &hFilterEnum);
    if (result != ERROR_SUCCESS)
    {
        FwpmEngineClose0(hEngine);
        printf("  [X] FwpmFilterCreateEnumHandle0 failed with code 0x%x.\n", result);
        return;
    }

    // Read and delete filters
    printf("[i] Reading and deleting filters from hardcoded provider\n");
    while (TRUE)
    {
        result = FwpmFilterEnum0(hEngine, hFilterEnum, 1, &filters, &numFilters);
        if (result != ERROR_SUCCESS)
        {
            printf("  [X] FwpmFilterEnum0 failed with code 0x%x.\n", result);
            return;
        }

        if (numFilters == 0)
        {
            break;
        }

        FWPM_DISPLAY_DATA0* data = &filters[0]->displayData;
        WCHAR* currentFilterName = data->name;
        if (wcscmp(currentFilterName, filterName) == 0) 
        {
            foundFilter = TRUE;
            UINT64 filterId = filters[0]->filterId;
            result = FwpmFilterDeleteById0(hEngine, filterId);
            if (result == ERROR_SUCCESS) 
            {
                printf("  [*] Deleted filter with id: 0x%x%x.\n", (UINT32)(filterId >> 32), (UINT32)(filterId & 0xFFFFFFFF));
            }
            else 
            {
                printf("  [X] Failed to delete filter with id: 0x%x%x and error code: 0x%x.\n", (UINT32)(filterId >> 32), (UINT32)(filterId & 0xFFFFFFFF), result);
            }
        }
    }

    if (!foundFilter)
    {
        printf("  [!] No filters found\n");
    }

    // Delete provider
    printf("[i] Deleting provider\n");
    result = FwpmProviderDeleteByKey0(hEngine, &providerKey);
    if (result != ERROR_SUCCESS)
    {
        printf("[X] FwpmProviderDeleteByKey0 failed with code 0x%x.\n", result);
        return;
    }

    FwpmFilterDestroyEnumHandle0(hEngine, hFilterEnum);
    FwpmEngineClose0(hEngine);
}

int main(int argc, char** argv)
{    
    if (argc < 2)
    {
        printf("Params:\n");
        printf("  - Create filters for a given process: \"create <process_full_path>\"\n");
        printf("  - Delete all filters: \"cleanall\"\n");
        return 1;
    }

    if (strcmp(argv[1], "create") == 0 && argc == 3)
    {
        create(argv[2]);
    }
    else if (strcmp(argv[1], "cleanall") == 0)
    {
        clean();
    }

    printf("Done!");
    return 0;
}