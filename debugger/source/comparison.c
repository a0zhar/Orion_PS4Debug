#include "../include/comparison.h"

// Compares if the memory value exactly matches the scan value for the given data type.
// This function performs a byte-by-byte comparison of the values.
int compare_exact_value(_BYTE* pScanValue, _BYTE* pMemoryValue, size_t valTypeLength) {
    for (size_t j = 0; j < valTypeLength; j++) {
        if (pScanValue[j] != pMemoryValue[j])
            return 0;
    }
    return 1;
}

// Compares if the memory value is within a small tolerance of the scan value for float or double types.
// This is a "fuzzy" comparison that allows small deviations, typically used for floating-point values.
int compare_fuzzy_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue) {
    if (valType == valTypeFloat) {
        float diff = *(float*)pScanValue - *(float*)pMemoryValue;
        return diff < 1.0f && diff > -1.0f;
    }

    if (valType == valTypeDouble) {
        double diff = *(double*)pScanValue - *(double*)pMemoryValue;
        return diff < 1.0 && diff > -1.0;
    }

    return 0;
}

// Compares if the memory value is greater than the extra value for the specified data type.
// This is used to detect values that have increased.
int compare_increased_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue) {
    switch (valType) {
        case valTypeUInt8:     return *pMemoryValue > *pExtraValue;
        case valTypeInt8:      return *(int8_t*)pMemoryValue > *(int8_t*)pExtraValue;
        case valTypeUInt16:    return *(uint16_t*)pMemoryValue > *(uint16_t*)pExtraValue;
        case valTypeInt16:     return *(int16_t*)pMemoryValue > *(int16_t*)pExtraValue;
        case valTypeUInt32:    return *(uint32_t*)pMemoryValue > *(uint32_t*)pExtraValue;
        case valTypeInt32:     return *(int32_t*)pMemoryValue > *(int32_t*)pExtraValue;
        case valTypeUInt64:    return *(uint64_t*)pMemoryValue > *(uint64_t*)pExtraValue;
        case valTypeInt64:     return *(int64_t*)pMemoryValue > *(int64_t*)pExtraValue;
        case valTypeFloat:     return *(float*)pMemoryValue > *(float*)pExtraValue;
        case valTypeDouble:    return *(double*)pMemoryValue > *(double*)pExtraValue;
        case valTypeArrBytes:
        case valTypeString:
        default:
            return 0;
    }
}

// Compares if the memory value is less than the extra value for the specified data type.
// This is used to detect values that have decreased.
int compare_decreased_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue) {
    switch (valType) {
        case valTypeUInt8:     return *pMemoryValue < *pExtraValue;
        case valTypeInt8:      return *(int8_t*)pMemoryValue < *(int8_t*)pExtraValue;
        case valTypeUInt16:    return *(uint16_t*)pMemoryValue < *(uint16_t*)pExtraValue;
        case valTypeInt16:     return *(int16_t*)pMemoryValue < *(int16_t*)pExtraValue;
        case valTypeUInt32:    return *(uint32_t*)pMemoryValue < *(uint32_t*)pExtraValue;
        case valTypeInt32:     return *(int32_t*)pMemoryValue < *(int32_t*)pExtraValue;
        case valTypeUInt64:    return *(uint64_t*)pMemoryValue < *(uint64_t*)pExtraValue;
        case valTypeInt64:     return *(int64_t*)pMemoryValue < *(int64_t*)pExtraValue;
        case valTypeFloat:     return *(float*)pMemoryValue < *(float*)pExtraValue;
        case valTypeDouble:    return *(double*)pMemoryValue < *(double*)pExtraValue;
        case valTypeArrBytes:
        case valTypeString:
        default:
            return 0;
    };
}

// Compares if the memory value is different from the extra value for the specified data type.
// This checks if the value has changed (not equal).
int compare_changed_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue) {
    switch (valType) {
        case valTypeUInt8:     return *pMemoryValue != *pExtraValue;
        case valTypeInt8:      return *(int8_t*)pMemoryValue != *(int8_t*)pExtraValue;
        case valTypeUInt16:    return *(uint16_t*)pMemoryValue != *(uint16_t*)pExtraValue;
        case valTypeInt16:     return *(int16_t*)pMemoryValue != *(int16_t*)pExtraValue;
        case valTypeUInt32:    return *(uint32_t*)pMemoryValue != *(uint32_t*)pExtraValue;
        case valTypeInt32:     return *(int32_t*)pMemoryValue != *(int32_t*)pExtraValue;
        case valTypeUInt64:    return *(uint64_t*)pMemoryValue != *(uint64_t*)pExtraValue;
        case valTypeInt64:     return *(int64_t*)pMemoryValue != *(int64_t*)pExtraValue;
        case valTypeFloat:     return *(float*)pMemoryValue != *(float*)pExtraValue;
        case valTypeDouble:    return *(double*)pMemoryValue != *(double*)pExtraValue;
        case valTypeArrBytes:
        case valTypeString:
        default:
            return 0;
    };
}

// Compares if the memory value is equal to the extra value for the specified data type.
// This is used to check if the value has remained unchanged.
int compare_unchanged_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue) {
    switch (valType) {
        case valTypeUInt8:    return *pMemoryValue == *pExtraValue;
        case valTypeInt8:     return *(int8_t*)pMemoryValue == *(int8_t*)pExtraValue;
        case valTypeUInt16:   return *(uint16_t*)pMemoryValue == *(uint16_t*)pExtraValue;
        case valTypeInt16:    return *(int16_t*)pMemoryValue == *(int16_t*)pExtraValue;
        case valTypeUInt32:   return *(uint32_t*)pMemoryValue == *(uint32_t*)pExtraValue;
        case valTypeInt32:    return *(int32_t*)pMemoryValue == *(int32_t*)pExtraValue;
        case valTypeUInt64:   return *(uint64_t*)pMemoryValue == *(uint64_t*)pExtraValue;
        case valTypeInt64:    return *(int64_t*)pMemoryValue == *(int64_t*)pExtraValue;
        case valTypeFloat:    return *(float*)pMemoryValue == *(float*)pExtraValue;
        case valTypeDouble:   return *(double*)pMemoryValue == *(double*)pExtraValue;
        case valTypeArrBytes:
        case valTypeString:
        default:
            return 0;
    }
}

// Compares if the memory value is greater than the scan value for the specified data type.
// This helper function is used for checking if a value is greater than another.
int compare_bigger_than(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue) {
    switch (valType) {
        case valTypeUInt8:      return *(uint8_t*)pMemoryValue > *(uint8_t*)pScanValue;
        case valTypeInt8:       return *(int8_t*)pMemoryValue > *(int8_t*)pScanValue;
        case valTypeUInt16:     return *(uint16_t*)pMemoryValue > *(uint16_t*)pScanValue;
        case valTypeInt16:      return *(int16_t*)pMemoryValue > *(int16_t*)pScanValue;
        case valTypeUInt32:     return *(uint32_t*)pMemoryValue > *(uint32_t*)pScanValue;
        case valTypeInt32:      return *(int32_t*)pMemoryValue > *(int32_t*)pScanValue;
        case valTypeUInt64:     return *(uint64_t*)pMemoryValue > *(uint64_t*)pScanValue;
        case valTypeInt64:      return *(int64_t*)pMemoryValue > *(int64_t*)pScanValue;
        case valTypeFloat:      return *(float*)pMemoryValue > *(float*)pScanValue;
        case valTypeDouble:     return *(double*)pMemoryValue > *(double*)pScanValue;
        default:
            return 0;
    }
}

// Compares if the memory value is smaller than the scan value for the specified data type.
// This helper function is used for checking if a value is smaller than another.
int compare_smaller_than(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue) {
    switch (valType) {
        case valTypeUInt8:      return *(uint8_t*)pMemoryValue < *(uint8_t*)pScanValue;
        case valTypeInt8:       return *(int8_t*)pMemoryValue < *(int8_t*)pScanValue;
        case valTypeUInt16:     return *(uint16_t*)pMemoryValue < *(uint16_t*)pScanValue;
        case valTypeInt16:      return *(int16_t*)pMemoryValue < *(int16_t*)pScanValue;
        case valTypeUInt32:     return *(uint32_t*)pMemoryValue < *(uint32_t*)pScanValue;
        case valTypeInt32:      return *(int32_t*)pMemoryValue < *(int32_t*)pScanValue;
        case valTypeUInt64:     return *(uint64_t*)pMemoryValue < *(uint64_t*)pScanValue;
        case valTypeInt64:      return *(int64_t*)pMemoryValue < *(int64_t*)pScanValue;
        case valTypeFloat:      return *(float*)pMemoryValue < *(float*)pScanValue;
        case valTypeDouble:     return *(double*)pMemoryValue < *(double*)pScanValue;
        default: return 0;
    }
}
// Helper function for increased value by specific amount comparison
int compare_increased_value_by(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue) {
    switch (valType) {
        case valTypeUInt8:      return *(uint8_t*)pMemoryValue == *(uint8_t*)pScanValue + *(uint8_t*)pExtraValue;
        case valTypeInt8:       return *(int8_t*)pMemoryValue == *(int8_t*)pScanValue + *(int8_t*)pExtraValue;
        case valTypeUInt16:     return *(uint16_t*)pMemoryValue == *(uint16_t*)pScanValue + *(uint16_t*)pExtraValue;
        case valTypeInt16:      return *(int16_t*)pMemoryValue == *(int16_t*)pScanValue + *(int16_t*)pExtraValue;
        case valTypeUInt32:     return *(uint32_t*)pMemoryValue == *(uint32_t*)pScanValue + *(uint32_t*)pExtraValue;
        case valTypeInt32:      return *(int32_t*)pMemoryValue == *(int32_t*)pScanValue + *(int32_t*)pExtraValue;
        case valTypeUInt64:     return *(uint64_t*)pMemoryValue == *(uint64_t*)pScanValue + *(uint64_t*)pExtraValue;
        case valTypeInt64:      return *(int64_t*)pMemoryValue == *(int64_t*)pScanValue + *(int64_t*)pExtraValue;
        case valTypeFloat:      return *(float*)pMemoryValue == *(float*)pScanValue + *(float*)pExtraValue;
        case valTypeDouble:     return *(double*)pMemoryValue == *(double*)pScanValue + *(double*)pExtraValue;
        default: return 0;
    }
}

// Helper function for decreased value by specific amount comparison
int compare_decreased_value_by(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue) {
    switch (valType) {
        case valTypeUInt8:      return *(uint8_t*)pMemoryValue == *(uint8_t*)pScanValue - *(uint8_t*)pExtraValue;
        case valTypeInt8:       return *(int8_t*)pMemoryValue == *(int8_t*)pScanValue - *(int8_t*)pExtraValue;
        case valTypeUInt16:     return *(uint16_t*)pMemoryValue == *(uint16_t*)pScanValue - *(uint16_t*)pExtraValue;
        case valTypeInt16:      return *(int16_t*)pMemoryValue == *(int16_t*)pScanValue - *(int16_t*)pExtraValue;
        case valTypeUInt32:     return *(uint32_t*)pMemoryValue == *(uint32_t*)pScanValue - *(uint32_t*)pExtraValue;
        case valTypeInt32:      return *(int32_t*)pMemoryValue == *(int32_t*)pScanValue - *(int32_t*)pExtraValue;
        case valTypeUInt64:     return *(uint64_t*)pMemoryValue == *(uint64_t*)pScanValue - *(uint64_t*)pExtraValue;
        case valTypeInt64:      return *(int64_t*)pMemoryValue == *(int64_t*)pScanValue - *(int64_t*)pExtraValue;
        case valTypeFloat:      return *(float*)pMemoryValue == *(float*)pScanValue - *(float*)pExtraValue;
        case valTypeDouble:     return *(double*)pMemoryValue == *(double*)pScanValue - *(double*)pExtraValue;
        default: return 0;
    }
}

#define COMPARE_IN_RANGE(val, min, max) (val > min && val < max)
int compare_value_between(_BYTE* pMemoryValue, _BYTE* pScanValue, _BYTE* pExtraValue, ProcScanValueType valType) {
    // Helper macro to compare values within a range for types that support them
    switch (valType) {
        case valTypeUInt8: {
            uint8_t memValue = *pMemoryValue;
            uint8_t scanValue = *pScanValue;
            uint8_t extraValue = *pExtraValue;
            uint8_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            uint8_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeInt8: {
            int8_t memValue = *(int8_t*)pMemoryValue;
            int8_t scanValue = *(int8_t*)pScanValue;
            int8_t extraValue = *(int8_t*)pExtraValue;
            int8_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            int8_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeUInt16: {
            uint16_t memValue = *(uint16_t*)pMemoryValue;
            uint16_t scanValue = *(uint16_t*)pScanValue;
            uint16_t extraValue = *(uint16_t*)pExtraValue;
            uint16_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            uint16_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeInt16: {
            int16_t memValue = *(int16_t*)pMemoryValue;
            int16_t scanValue = *(int16_t*)pScanValue;
            int16_t extraValue = *(int16_t*)pExtraValue;
            int16_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            int16_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeUInt32: {
            uint32_t memValue = *(uint32_t*)pMemoryValue;
            uint32_t scanValue = *(uint32_t*)pScanValue;
            uint32_t extraValue = *(uint32_t*)pExtraValue;
            uint32_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            uint32_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeInt32: {
            int32_t memValue = *(int32_t*)pMemoryValue;
            int32_t scanValue = *(int32_t*)pScanValue;
            int32_t extraValue = *(int32_t*)pExtraValue;
            int32_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            int32_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeUInt64: {
            uint64_t memValue = *(uint64_t*)pMemoryValue;
            uint64_t scanValue = *(uint64_t*)pScanValue;
            uint64_t extraValue = *(uint64_t*)pExtraValue;
            uint64_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            uint64_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeInt64: {
            int64_t memValue = *(int64_t*)pMemoryValue;
            int64_t scanValue = *(int64_t*)pScanValue;
            int64_t extraValue = *(int64_t*)pExtraValue;
            int64_t minVal = (scanValue < extraValue) ? scanValue : extraValue;
            int64_t maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeFloat: {
            float memValue = *(float*)pMemoryValue;
            float scanValue = *(float*)pScanValue;
            float extraValue = *(float*)pExtraValue;
            float minVal = (scanValue < extraValue) ? scanValue : extraValue;
            float maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeDouble: {
            double memValue = *(double*)pMemoryValue;
            double scanValue = *(double*)pScanValue;
            double extraValue = *(double*)pExtraValue;
            double minVal = (scanValue < extraValue) ? scanValue : extraValue;
            double maxVal = (scanValue < extraValue) ? extraValue : scanValue;
            return COMPARE_IN_RANGE(memValue, minVal, maxVal);
        }
        case valTypeArrBytes:
        case valTypeString:
        default: return 0;
    };
}