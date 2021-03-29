package cloudwatchevents_test

import (
	"testing"

	tfevents "github.com/terraform-providers/terraform-provider-aws/aws/internal/service/cloudwatchevents"
)

func TestRuleParseID(t *testing.T) {
	testCases := []struct {
		TestName      string
		InputID       string
		ExpectedError bool
		ExpectedPart0 string
		ExpectedPart1 string
	}{
		{
			TestName:      "empty ID",
			InputID:       "",
			ExpectedError: true,
		},
		{
			TestName:      "single part",
			InputID:       "TestRule",
			ExpectedPart0: "default",
			ExpectedPart1: "TestRule",
		},
		{
			TestName:      "two parts",
			InputID:       "TestEventBus/TestRule",
			ExpectedPart0: "TestEventBus",
			ExpectedPart1: "TestRule",
		},
		{
			TestName:      "partner event bus",
			InputID:       "aws.partner/example.com/Test/TestRule",
			ExpectedPart0: "aws.partner/example.com/Test",
			ExpectedPart1: "TestRule",
		},
		{
			TestName:      "empty both parts",
			InputID:       "/",
			ExpectedError: true,
		},
		{
			TestName:      "empty first part",
			InputID:       "TestEventBus/",
			ExpectedError: true,
		},
		{
			TestName:      "empty second part",
			InputID:       "/TestRule",
			ExpectedError: true,
		},
		{
			TestName:      "three parts",
			InputID:       "TestEventBus/TestRule/Suffix",
			ExpectedError: true,
		},
		{
			TestName:      "four parts",
			InputID:       "abc.partner/TestEventBus/TestRule/Suffix",
			ExpectedError: true,
		},
		{
			TestName:      "five parts",
			InputID:       "test/aws.partner/example.com/Test/TestRule",
			ExpectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			gotPart0, gotPart1, err := tfevents.RuleParseID(testCase.InputID)

			if err == nil && testCase.ExpectedError {
				t.Fatalf("expected error, got no error")
			}

			if err != nil && !testCase.ExpectedError {
				t.Fatalf("got unexpected error: %s", err)
			}

			if gotPart0 != testCase.ExpectedPart0 {
				t.Errorf("got part 0 %s, expected %s", gotPart0, testCase.ExpectedPart0)
			}

			if gotPart1 != testCase.ExpectedPart1 {
				t.Errorf("got part 0 %s, expected %s", gotPart1, testCase.ExpectedPart1)
			}
		})
	}
}
