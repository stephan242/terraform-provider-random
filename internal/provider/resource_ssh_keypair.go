package provider

import (
	"fmt"

	"github.com/charmbracelet/keygen"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

var supportedKeys = []string{"rsa", "ed25519", "ecdsa"}

func validateKeyType(v interface{}, p cty.Path) diag.Diagnostics {
	value := v.(string)
	var diags diag.Diagnostics
	happy := false
	for _, sk := range supportedKeys {
		if value == sk {
			happy = true
		}
	}
	if happy == false {
		diag := diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "wrong keytype",
			Detail:   fmt.Sprintf("%q is not a supported keytype", value),
		}
		diags = append(diags, diag)
	}
	return diags
}

func resourceSshKeyPair() *schema.Resource {
	return &schema.Resource{
		Description: "The resource `random_ssh_keypair` generates a random ssh key pair that is intended to be " +
			"used for other resources.\n" +
			"\n" +
			"This resource uses TODO",
		Create: CreateSshKeyPair,
		Read:   schema.Noop,
		Delete: schema.RemoveFromState,
		Importer: &schema.ResourceImporter{
			State: ImportSshKeyPair,
		},

		Schema: map[string]*schema.Schema{
			"keytype": {
				Description:      "SSH key type",
				Type:             schema.TypeString,
				Optional:         true,
				Default:          "rsa",
				ForceNew:         true,
				ValidateDiagFunc: validateKeyType,
			},

			"pubkey": {
				Description: "The generated public key",
				Type:        schema.TypeString,
				Computed:    true,
			},

			"privkey": {
				Description: "The generated private key",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func convertPubKey(in []byte) (ssh.PublicKey, error) {
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(in)
	if err != nil {
		return nil, err
	}
	resPubKey, err := ssh.ParsePublicKey(parsedKey.Marshal())
	if err != nil {
		return nil, err
	}

	return resPubKey, nil
}

func CreateSshKeyPair(d *schema.ResourceData, meta interface{}) error {

	keytype := keygen.KeyType(d.Get("keytype").(string))

	key, err := keygen.New("thepath", "thekey", []byte(""), keytype)
	if err != nil {
		return fmt.Errorf("error generating keypair: %v", err)
	}

	pk, err := convertPubKey(key.PublicKey)
	if err != nil {
		return fmt.Errorf("error converting public key: %v", err)
	}

	d.Set("privkey", string(key.PrivateKeyPEM))
	d.Set("pubkey", string(ssh.MarshalAuthorizedKey(pk)))
	d.SetId(ssh.FingerprintSHA256(pk))

	return nil
}

func ImportSshKeyPair(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	return nil, nil
}

//https://pkg.go.dev/github.com/charmbracelet/keygen#section-readme
