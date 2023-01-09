package iam

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func DataSourceUserSSHKey() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceUserSSHKeyRead,
		Schema: map[string]*schema.Schema{
			"encoding": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					iam.EncodingTypeSsh,
					iam.EncodingTypePem,
				}, false),
			},
			"fingerprint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"public_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ssh_public_key_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"username": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceUserSSHKeyRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).IAMConn()

	encoding := d.Get("encoding").(string)
	sshPublicKeyId := d.Get("ssh_public_key_id").(string)
	username := d.Get("username").(string)

	request := &iam.GetSSHPublicKeyInput{
		Encoding:       aws.String(encoding),
		SSHPublicKeyId: aws.String(sshPublicKeyId),
		UserName:       aws.String(username),
	}

	response, err := conn.GetSSHPublicKey(request)
	if err != nil {
		return fmt.Errorf("error reading IAM User SSH Key: %w", err)
	}

	publicKey := response.SSHPublicKey
	publicKeyBody := publicKey.SSHPublicKeyBody
	if encoding == iam.EncodingTypeSsh {
		publicKeyBody = aws.String(cleanSSHKey(aws.StringValue(publicKeyBody)))
	}

	d.SetId(aws.StringValue(publicKey.SSHPublicKeyId))
	d.Set("fingerprint", publicKey.Fingerprint)
	d.Set("public_key", publicKeyBody)
	d.Set("status", publicKey.Status)

	return nil
}
