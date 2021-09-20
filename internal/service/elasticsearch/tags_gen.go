// Code generated by internal/generate/tags/main.go; DO NOT EDIT.

package elasticsearch

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elasticsearchservice"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
)

// ListTags lists elasticsearch service tags.
// The identifier is typically the Amazon Resource Name (ARN), although
// it may also be a different identifier depending on the service.
func ListTags(conn *elasticsearchservice.ElasticsearchService, identifier string) (tftags.KeyValueTags, error) {
	input := &elasticsearchservice.ListTagsInput{
		ARN: aws.String(identifier),
	}

	output, err := conn.ListTags(input)

	if err != nil {
		return tftags.New(nil), err
	}

	return KeyValueTags(output.TagList), nil
}

// []*SERVICE.Tag handling

// Tags returns elasticsearch service tags.
func Tags(tags tftags.KeyValueTags) []*elasticsearchservice.Tag {
	result := make([]*elasticsearchservice.Tag, 0, len(tags))

	for k, v := range tags.Map() {
		tag := &elasticsearchservice.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}

		result = append(result, tag)
	}

	return result
}

// KeyValueTags creates tftags.KeyValueTags from elasticsearchservice service tags.
func KeyValueTags(tags []*elasticsearchservice.Tag) tftags.KeyValueTags {
	m := make(map[string]*string, len(tags))

	for _, tag := range tags {
		m[aws.StringValue(tag.Key)] = tag.Value
	}

	return tftags.New(m)
}

// UpdateTags updates elasticsearch service tags.
// The identifier is typically the Amazon Resource Name (ARN), although
// it may also be a different identifier depending on the service.
func UpdateTags(conn *elasticsearchservice.ElasticsearchService, identifier string, oldTagsMap interface{}, newTagsMap interface{}) error {
	oldTags := tftags.New(oldTagsMap)
	newTags := tftags.New(newTagsMap)

	if removedTags := oldTags.Removed(newTags); len(removedTags) > 0 {
		input := &elasticsearchservice.RemoveTagsInput{
			ARN:     aws.String(identifier),
			TagKeys: aws.StringSlice(removedTags.IgnoreAws().Keys()),
		}

		_, err := conn.RemoveTags(input)

		if err != nil {
			return fmt.Errorf("error untagging resource (%s): %w", identifier, err)
		}
	}

	if updatedTags := oldTags.Updated(newTags); len(updatedTags) > 0 {
		input := &elasticsearchservice.AddTagsInput{
			ARN:     aws.String(identifier),
			TagList: Tags(updatedTags.IgnoreAws()),
		}

		_, err := conn.AddTags(input)

		if err != nil {
			return fmt.Errorf("error tagging resource (%s): %w", identifier, err)
		}
	}

	return nil
}
