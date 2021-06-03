package iotwireless

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iotwireless"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
)

func ResourceDeviceProfile() *schema.Resource {
	return &schema.Resource{
		Create: resourceDeviceProfileCreate,
		Read:   resourceDeviceProfileRead,
		Update: resourceDeviceProfileUpdate,
		Delete: resourceDeviceProfileDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"lorawan": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"class_b_timeout": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"class_c_timeout": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"factory_preset_freqs_list": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeInt,
							},
						},

						"mac_version": {
							Type:     schema.TypeString,
							Required: true,
						},

						"max_duty_cycle": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"max_eirp": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"ping_slot_dr": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"ping_slot_freq": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntAtLeast(1e+06),
						},

						"ping_slot_period": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntAtLeast(128),
						},

						"reg_params_revision": {
							Type:     schema.TypeString,
							Required: true,
						},

						"rf_region": {
							Type:     schema.TypeString,
							Required: true,
						},

						"rx_data_rate_2": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"rx_delay_1": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"rx_dr_offset_1": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						"rx_freq_2": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntAtLeast(1e+06),
						},

						"supports_32bit_fcnt": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"supports_class_b": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"supports_class_c": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"supports_join": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
			},
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tags":     tftags.TagsSchema(),
			"tags_all": tftags.TagsSchemaComputed(),
		},
	}
}

func resourceDeviceProfileCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).IoTWirelessConn
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	tags := defaultTagsConfig.MergeTags(tftags.New(d.Get("tags").(map[string]interface{})))

	params := &iotwireless.CreateDeviceProfileInput{
		Name: aws.String(d.Get("name").(string)),
		Tags: Tags(tags.IgnoreAWS()),
	}

	if lorawan, ok := d.GetOk("lorawan"); ok {
		l := lorawan.([]interface{})
		params.LoRaWAN = &iotwireless.LoRaWANDeviceProfile{}

		if val, ok := l[0].(map[string]interface{})["class_b_timeout"]; ok {
			params.LoRaWAN.ClassBTimeout = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["class_c_timeout"]; ok {
			params.LoRaWAN.ClassCTimeout = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["factory_preset_freqs_list"]; ok {
			list := val.([]interface{})
			log.Printf("[DEBUG] List is: %v", list)
			for _, v := range list {
				log.Printf("[DEBUG] v is %v of type %T", v, v)
				presetFreq, ok := v.(int)
				if !ok {
					return fmt.Errorf("not int type found in factory_preset_freqs_list: %v", list)
				}
				params.LoRaWAN.FactoryPresetFreqsList = append(params.LoRaWAN.FactoryPresetFreqsList, aws.Int64(int64(presetFreq)))
			}
		}
		if val, ok := l[0].(map[string]interface{})["mac_version"]; ok {
			params.LoRaWAN.MacVersion = aws.String(val.(string))
		}
		if val, ok := l[0].(map[string]interface{})["max_duty_cycle"]; ok {
			params.LoRaWAN.MaxDutyCycle = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["max_eirp"]; ok {
			params.LoRaWAN.MaxEirp = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["ping_slot_dr"]; ok {
			params.LoRaWAN.PingSlotDr = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["ping_slot_freq"]; ok {
			pingSlotFreq := int64(val.(int))
			if pingSlotFreq != 0 {
				params.LoRaWAN.PingSlotFreq = aws.Int64(pingSlotFreq)
			}
		}
		if val, ok := l[0].(map[string]interface{})["ping_slot_period"]; ok {
			pingSlotPeriod := int64(val.(int))
			if pingSlotPeriod != 0 {
				params.LoRaWAN.PingSlotPeriod = aws.Int64(pingSlotPeriod)
			}
		}
		if val, ok := l[0].(map[string]interface{})["reg_params_revision"]; ok {
			params.LoRaWAN.RegParamsRevision = aws.String(val.(string))
		}
		if val, ok := l[0].(map[string]interface{})["rf_region"]; ok {
			params.LoRaWAN.RfRegion = aws.String(val.(string))
		}
		if val, ok := l[0].(map[string]interface{})["rx_data_rate_2"]; ok {
			params.LoRaWAN.RxDataRate2 = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["rx_delay_1"]; ok {
			params.LoRaWAN.RxDelay1 = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["rx_dr_offset_1"]; ok {
			params.LoRaWAN.RxDrOffset1 = aws.Int64(int64(val.(int)))
		}
		if val, ok := l[0].(map[string]interface{})["rx_freq_2"]; ok {
			rxFreq2 := int64(val.(int))
			if rxFreq2 != 0 {
				params.LoRaWAN.RxFreq2 = aws.Int64(rxFreq2)
			}
		}
		if val, ok := l[0].(map[string]interface{})["supports_32bit_fcnt"]; ok {
			params.LoRaWAN.Supports32BitFCnt = aws.Bool(val.(bool))
		}
		if val, ok := l[0].(map[string]interface{})["supports_class_b"]; ok {
			params.LoRaWAN.SupportsClassB = aws.Bool(val.(bool))
		}
		if val, ok := l[0].(map[string]interface{})["supports_class_c"]; ok {
			params.LoRaWAN.SupportsClassC = aws.Bool(val.(bool))
		}
		if val, ok := l[0].(map[string]interface{})["supports_join"]; ok {
			params.LoRaWAN.SupportsJoin = aws.Bool(val.(bool))
		}
	}

	log.Printf("[DEBUG] Creating IoT Wireless Device Profile: %s", params)
	out, err := conn.CreateDeviceProfile(params)
	if err != nil {
		return err
	}

	d.SetId(aws.StringValue(out.Id))

	return resourceDeviceProfileRead(d, meta)
}

func resourceDeviceProfileRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).IoTWirelessConn
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	ignoreTagsConfig := meta.(*conns.AWSClient).IgnoreTagsConfig

	params := &iotwireless.GetDeviceProfileInput{
		Id: aws.String(d.Id()),
	}
	log.Printf("[DEBUG] Reading IoT Wireless Device Profile: %s", params)
	out, err := conn.GetDeviceProfile(params)

	if err != nil {
		if tfawserr.ErrCodeEquals(err, iotwireless.ErrCodeResourceNotFoundException) {
			log.Printf("[WARN] IoT Wireless Device Profile %q not found, removing from state", d.Id())
			d.SetId("")
		}
		return err
	}

	log.Printf("[DEBUG] Received IoT Wireless Device Profile: %s", out)

	d.Set("arn", out.Arn)
	d.Set("name", out.Name)

	lorawan := make([]map[string]interface{}, 0, 1)
	l := make(map[string]interface{})

	l["class_b_timeout"] = out.LoRaWAN.ClassBTimeout
	l["class_c_timeout"] = out.LoRaWAN.ClassCTimeout
	if out.LoRaWAN.FactoryPresetFreqsList != nil && len(out.LoRaWAN.FactoryPresetFreqsList) > 0 {
		l["factory_preset_freqs_list"] = out.LoRaWAN.FactoryPresetFreqsList
	}
	l["mac_version"] = out.LoRaWAN.MacVersion
	l["max_duty_cycle"] = out.LoRaWAN.MaxDutyCycle
	l["max_eirp"] = out.LoRaWAN.MaxEirp
	l["ping_slot_dr"] = out.LoRaWAN.PingSlotDr
	if aws.Int64Value(out.LoRaWAN.PingSlotFreq) != 0 {
		l["ping_slot_freq"] = aws.Int64Value(out.LoRaWAN.PingSlotFreq)
	}
	if aws.Int64Value(out.LoRaWAN.PingSlotPeriod) != 0 {
		l["ping_slot_period"] = aws.Int64Value(out.LoRaWAN.PingSlotPeriod)
	}
	l["reg_params_revision"] = out.LoRaWAN.RegParamsRevision
	l["rf_region"] = out.LoRaWAN.RfRegion
	l["rx_data_rate_2"] = out.LoRaWAN.RxDataRate2
	l["rx_delay_1"] = out.LoRaWAN.RxDelay1
	l["rx_dr_offset_1"] = out.LoRaWAN.RxDrOffset1
	if aws.Int64Value(out.LoRaWAN.RxFreq2) != 0 {
		l["rx_freq_2"] = aws.Int64Value(out.LoRaWAN.RxFreq2)
	}
	l["supports_32bit_fcnt"] = out.LoRaWAN.Supports32BitFCnt
	l["supports_class_b"] = out.LoRaWAN.SupportsClassB
	l["supports_class_c"] = out.LoRaWAN.SupportsClassC
	l["supports_join"] = out.LoRaWAN.SupportsJoin

	lorawan = append(lorawan, l)
	if err := d.Set("lorawan", lorawan); err != nil {
		return fmt.Errorf("error setting lorawan: %s", err)
	}

	arn := aws.StringValue(out.Arn)

	d.Set("arn", arn)

	tags, err := ListTags(conn, arn)

	if err != nil {
		return fmt.Errorf("listing tags for IoT Wireless Device Profile (%s): %w", arn, err)
	}

	tags = tags.IgnoreAWS().IgnoreConfig(ignoreTagsConfig)

	//lintignore:AWSR002
	if err := d.Set("tags", tags.RemoveDefaultConfig(defaultTagsConfig).Map()); err != nil {
		return fmt.Errorf("setting tags: %w", err)
	}

	if err := d.Set("tags_all", tags.Map()); err != nil {
		return fmt.Errorf("setting tags_all: %w", err)
	}

	return nil
}

func resourceDeviceProfileUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).IoTWirelessConn

	if d.HasChangesExcept("tags", "tags_all") {
		return fmt.Errorf("should force new")
	}

	if d.HasChange("tags_all") {
		o, n := d.GetChange("tags_all")

		if err := UpdateTags(conn, d.Get("arn").(string), o, n); err != nil {
			return fmt.Errorf("updating tags: %w", err)
		}
	}

	return resourceDeviceProfileRead(d, meta)
}

func resourceDeviceProfileDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).IoTWirelessConn

	params := &iotwireless.DeleteDeviceProfileInput{
		Id: aws.String(d.Id()),
	}
	log.Printf("[DEBUG] Deleting IoT Wireless Device Profile: %s", params)

	_, err := conn.DeleteDeviceProfile(params)
	if err != nil {
		if tfawserr.ErrCodeEquals(err, iotwireless.ErrCodeResourceNotFoundException) {
			return nil
		}
		return err
	}

	return nil
}
