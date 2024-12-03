package main

import (
	"fmt"
	"os"
	"sophuwu.site/seks"
	"strings"
)

// Private Protected Some Encryption Key Stuff

func hmenu(s *string) {
	u := []string{
		`\|`, `\0|\1`,
		`\1`, "\033[1;38;5;9m",
		`\2`, "\033[1;38;5;10m",
		`{{ argv }}`, fmt.Sprintf(`\3%s\0`, os.Args[0]),
		`\3`, "\033[38;5;11m",
		`\$`, `\4$`,
		`\4`, "\033[38;2;200;30;200m",
		`\0`, "\033[0m",
	}
	for i := 0; i < len(u); i += 2 {
		*s = strings.ReplaceAll(*s, u[i], u[i+1])
	}
	fmt.Print(*s)
	os.Exit(0)
}

var helpLong = `Usage: {{ argv }} \1h\|e\|d\|i\|k\|s\|l\0 <\2option\0> [\1-i\|-o\0 \2file\0]

\1h\0elp	  		   - get help with SEKS, h will show short usage information

protected private secret encryption key string


\1e\0ncrypt	  \2name\0 - encrypt with public key \2name\0 and sign using default key
\1d\0ecrypt	  \2name\0 - verify using public key \2name\0 and decrypt using default key


\1i\0mport	  \2name\0 - import an existing key into the \$SEKSZONE\0 as \2name\0
\1s\0etdefs	  \2name\0 - set \2name\0 as the default key for signing and decrypting
\1k\0eygen	  \2name\0 - create a new pair of PPSEKS (protected private secret encryption key string)
						 
						 Use the  to sign and decrypt.
						 with SEKS (U Shared Encryption Key String)

\1l\0ist	  \2term\0 - print public SEKS keys in the \$SEKSZONE\0 matching \2term\0

\1DisplayPP\0 \2name\0 - detailed information for protected private SEKS key \2name\0
\1DumpPPCatalog\0      - dump all protected \1private\0 SEKS keys cataloged from the \$SEKSZONE\0

The first letter of any command can be used as a shortcut. For example, \1e\0 is the same as \1encrypt\0.
Except the DisplayPP DumpPPCatalog, as they output protected private SEKS key information.  

By default {{ argv }} reads from stdin and writes to stdout. Using a pipe is 
recommended for large files. However, \1-i\0 and \1-o\0 can be used to specify input
and output files. This will overwrite the output file without warning.

By default, {{ argv }} will use \4~/.sekszone\0 for configuration and key storage. This
can be changed by setting the environment variable \$SEKSZONE\0 to an empty directory or 
existing SEKS ZONE . The permissions of this directory can be whatever you like,
but it is a good idea to ensure that only your user can access the SEKS ZONE.

\$PPSEKS\0 can be used to specify a protected private secret encryption key string
to use instead of the default PPSEKS.
`
var shortHelp = `{{ argv }} e|d <\2key\0> [\1-i\|-o\0 \2file\0]
\1e\0ncrypt		\1d\0ecrypt		\1-o\0 overwrites without warning
find full help with "{{ argv }} help"

\$PPSEKS\0 can change the default key for signing and decrypting.

Use {{ argv }} help for more usage information.
`

func init() {
	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "h" {
		hmenu(&shortHelp)
	} else if os.Args[1] == "help" || os.Args[1] == "--help" {
		hmenu(&helpLong)
	}
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "g" || os.Args[1] == "keygen") {
		pub, priv := seks.KeyGen()
		fmt.Println(pub)
		fmt.Println(priv)
		return
	}
	if len(os.Args) != 5 {
		return
	}
	keys := make(map[byte]string)
	keys[os.Args[2][0]] = os.Args[2]
	keys[os.Args[3][0]] = os.Args[3]
	b, err := os.ReadFile(os.Args[4])
	if err != nil {
		fmt.Println(err)
		return
	}
	if os.Args[1] == "e" {
		b, err = seks.EncryptArmour(b, keys['p'], keys['S'])
	} else if os.Args[1] == "d" {
		b, err = seks.DecryptArmour(b, keys['p'], keys['S'])
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
}
