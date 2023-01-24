package ssmincidents

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssmincidents/types"
)

func ExpandRegions(regions []interface{}) map[string]types.RegionMapInputValue {
	if len(regions) == 0 {
		return nil
	}

	return GenerateMapFromList(
		regions,
		func(region interface{}) string {
			return region.(map[string]interface{})["name"].(string)
		},
		func(region interface{}) types.RegionMapInputValue {
			regionData := region.(map[string]interface{})

			input := types.RegionMapInputValue{}

			if kmsKey := regionData["kms_key_arn"].(string); kmsKey != "DefaultKey" {
				input.SseKmsKeyId = aws.String(kmsKey)
			}

			return input
		},
	)
}

func FlattenRegions(regions map[string]types.RegionInfo) []map[string]interface{} {
	if len(regions) == 0 {
		return nil
	}

	return GenerateListFromMap(
		regions,
		func(regionName string, regionData types.RegionInfo) map[string]interface{} {
			region := make(map[string]interface{})

			region["name"] = regionName
			region["status"] = regionData.Status
			region["status_update_time"] = aws.ToTime(regionData.StatusUpdateDateTime).String()
			region["kms_key_arn"] = aws.ToString(regionData.SseKmsKeyId)
			region["status_message"] = aws.ToString(regionData.StatusMessage)

			return region
		},
	)
}
