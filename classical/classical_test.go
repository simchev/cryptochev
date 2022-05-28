package classical

import (
	"regexp"
	"strings"
	"testing"
)

var spaces = 5
var tests = [...]string{"WEAREDISCOVEREDFLEEATONCE", "WEATTACKAT1200AM", "YOUCANTSEEME", "WELOVEPAKISTANIDESTROYINDIA", "JOUBLIERAIJAMAISCETETE"}

func errorTest(t *testing.T, msg string, exp string, res string) {
	t.Errorf("%s. Expected: %s\nActual: %s", msg, ToSpaced(exp, spaces), ToSpaced(res, spaces))
}

func testCipher(t *testing.T, c ICipherClassical, exp string, test string) {
	c.Encrypt()
	ciphertext := string(c.GetText())
	if ciphertext != exp {
		errorTest(t, "Encrypt failed", exp, ciphertext)
	}

	c.Decrypt()
	plaintext := string(c.GetText())
	if plaintext != test {
		errorTest(t, "Decrypt failed", test, plaintext)
	}
}

func testCipherRegex(t *testing.T, c ICipherClassical, regex string, test string) {
	c.Encrypt()
	ciphertext := string(c.GetText())
	matched, err := regexp.MatchString(regex, ciphertext)
	if err != nil {
		t.Errorf("Regex error: %s, Error: %s", regex, err)
	} else if !matched {
		errorTest(t, "Encrypt failed", regex, ciphertext)
	}

	c.Decrypt()
	plaintext := string(c.GetText())
	if plaintext != test {
		errorTest(t, "Decrypt failed", test, plaintext)
	}
}

func TestSubstitute(t *testing.T) {
	alphabets := [...]string{AlphabetL, AlphabetL36, AlphabetL, AlphabetL25, AlphabetL}
	salphabets := [...]string{
		"0123456789!\"/$%?&*()±@£¢¤²", 
		"あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもん", 
		"一二三四五六七八九十人上下千百口土中女子円火犬猫本体", 
		"ΑΒΓΔδΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ", 
		"АБВГДЕЖꙂꙀИІКЛМНОПРСТФХѠЦЧШ",
	}
	expects := [...]string{
		"£40*438(2%@4*435\"440)%$24", 
		"ぬおあととあうさあとひふんんあす", 
		"本百円三一千子女五五下五", 
		"ΦδΚΝΥδΞΑΙΘΡΣΑΜΘΔδΡΣΠΝΨΘΜΔΘΑ", 
		"ИНФБКꙀДРАꙀИАЛАꙀСВДТДТД",
	}

	for i, test := range tests {
		c := NewSubstitute([]rune(test), NewKeySubstitute([]rune(alphabets[i]), []rune(salphabets[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestShift(t *testing.T) {
	shifts := [...]int{5, 10, -8, 3, 13}
	expects := [...]string{"\\JFWJINXHT[JWJIKQJJFYTSHJ", "aOK^^KMUK^;<::KW", "QGM;9FLK==E=", "ZHORYHSDNLVWDQLGHVWUR\\LQGLD", "W\\bOYVR_NVWNZNV`PRaRaR"}

	for i, test := range tests {
		c := NewShift([]rune(test), NewKeyShift(shifts[i]))
		testCipher(t, c, expects[i], test)
	}
}

func TestCaesar(t *testing.T) {
	shifts := [...]int{6, 2, -5, -11, 67}
	expects := [...]string{"CKGXKJOYIUBKXKJLRKKGZUTIK", "YGCVVCEMCV1200CO", "TJPXVIONZZHZ", "LTADKTEPZXHIPCXSTHIGDNXCSXP", "YDJQAXTGPXYPBPXHRTITIT"}

	for i, test := range tests {
		c := NewCaesar([]rune(test), NewKeyCaesar(shifts[i]))
		testCipher(t, c, expects[i], test)
	}
}

func TestROT13(t *testing.T) {
	expects := [...]string{"JRNERQVFPBIRERQSYRRNGBAPR", "JRNGGNPXNG1200NZ", "LBHPNAGFRRZR", "JRYBIRCNXVFGNAVQRFGEBLVAQVN", "WBHOYVRENVWNZNVFPRGRGR"}

	for i, test := range tests {
		c := NewROT13([]rune(test), NewKeyROT13())
		testCipher(t, c, expects[i], test)
	}
}

func TestVigenere(t *testing.T) {
	keys := [...]string{"", "LEMON", "MONSTEC", "CLEF", "SECRAT"}
	alphabets := [...]string{AlphabetL, AlphabetL36, "ACEMNOSTUY", AlphabetL, AlphabetL36}
	expects := [...]string{"WFCUIIOZKXFPDRRUBVWTNJJZC", "8IM87LGWO7B6LNNX", "EAETTSUYTSYY", "YPPTXPTFMTWYCYMIGDXWQJMSFTE", "2SWSL2WVCZJT5EK0CXBIVV"}

	for i, test := range tests {
		c := NewVigenere([]rune(test), NewKeyVigenere([]rune(alphabets[i]), []rune(keys[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestVigenereBeaufort(t *testing.T) {
	keys := [...]string{"", "LEMON", "MONSTEC", "CLEF", "SECRAT"}
	alphabets := [...]string{AlphabetL, AlphabetL36, "ACEMNOSTUY", AlphabetL, AlphabetL36}
	expects := [...]string{"WDYOAYCLUFLTFRPQVNMHZTRFG", "LAYFGZ99WGPXXVXB", "SANOMESMTUTO", "UTHJTTLVIXOOYCEYCHPMMNEIBXW", "2KSULZWN92JR57GBCVBARX"}

	for i, test := range tests {
		c := NewVigenereBeaufort([]rune(test), NewKeyVigenere([]rune(alphabets[i]), []rune(keys[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestVigenereGronsfeld(t *testing.T) {
	keys := [...]string{"15642", "23578", "", "15240", "0123"}
	alphabets := [...]string{AlphabetL, AlphabetL36, "ACEMNOSTUY", AlphabetL, AlphabetL36}
	expects := [...]string{"XJGVGENYGQWJXIFGQKICUTTGG", "YHF12CFPH235EGIO", "YSANNYMMACMM", "XJNSVFUCOITYCRIEJUXRPDKRDJF", "JPWELJGUAJLDMBKVCFVHTF"}

	for i, test := range tests {
		c := NewVigenereGronsfeld([]rune(test), NewKeyVigenere([]rune(alphabets[i]), []rune(keys[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestReverse(t *testing.T) {
	expects := [...]string{"ECNOTAEELFDEREVOCSIDERAEW", "MA0021TAKCATTAEW", "EMEESTNACUOY", "AIDNIYORTSEDINATSIKAPEVOLEW", "ETETECSIAMAJIAREILBUOJ"}

	for i, test := range tests {
		c := NewReverse([]rune(test), NewKeyReverse())
		testCipher(t, c, expects[i], test)
	}
}

func TestColumn(t *testing.T) {
	keys := [...]string{"CARGO", "ZEBRAS", "SPECIALUNITONE", "VERYBIGSECRET", "LEGRANDMANITOU"}
	expects := [...]string{"EIELOWDVFTRCEECEODAEASREN", "T1AAAEK0TTMA2WC0", "NCUAETEEOYMS", "VSIIEIKYTDPRETLDSNAOAIWNAOE", "LTAETOSUCJJIREIEIMBEAA"}
	expectsPad := [...]string{"^EIELOWDVFTRCEECEODAEASREN$", "^T1.AAAEK0TTMA2.WC0$", "^NCU.AETE.EOYMS$", "^VS.II.EI.KY.TD.PR.ET.LD.SN.AO.AI.WNAOE.$", "^LTA.ETOSUCJ.JIREIEI.M.BEA.A.$"}

	for i, test := range tests {
		key := NewKeyColumn([]rune(keys[i]))
		c := NewColumn([]rune(test), key)
		testCipher(t, c, expects[i], test)
		test2 := ToPadded(test, len([]rune(keys[i])))
		c2 := NewColumn([]rune(test2), key)
		testCipherRegex(t, c2, expectsPad[i], test2)
	}
}

func TestZigzag(t *testing.T) {
	keys := [...]int{5, 7, 3, 9, 1}
	expects := [...]string{"WCLEESOFECAIVDENRDEEAOERT", "W0E20A1ATTMTAAKC", "YAEOCNSEEUTM", "WEEDSLITONRVAOETYPSIAAINIKD", "JOUBLIERAIJAMAISCETETE"}

	for i, test := range tests {
		c := NewZigzag([]rune(test), NewKeyZigzag(keys[i]))
		testCipher(t, c, expects[i], test)
	}
}

func TestScytale(t *testing.T) {
	keys := [...]int{6, 2, 1, 11, 5}
	expects := [...]string{"WIREEESEAACDTROFOEVLNDEEC", "WATCA10AETAKT20M", "YOUCANTSEEME", "WTIEANLNDOIIVDAEEPSATKRIOSY", "JIJSTOEACEURMEBAATLIIE"}

	for i, test := range tests {
		c := NewScytale([]rune(test), NewKeyScytale(keys[i]))
		testCipher(t, c, expects[i], test)
	}
}

func TestRouteSpiral(t *testing.T) {
	widths := [...]int{ 6, 7, 3, 9, 1 }
	routes := [...]route{
		ROUTE_TLR,
		ROUTE_TLD,
		ROUTE_TRL,
		ROUTE_TRD,
		ROUTE_BLR,
		ROUTE_BLU,
		ROUTE_BRL,
		ROUTE_BRU,
	}
	expects := [...][]string{
		{ "WEAREDEECEERISCOVLNOTAEDF", "WIREECEEDERAESEATONLVOCDF", "DERAEWIREECEEVOCSEATONLFD", "DEECEERIWEAREVLNOTAESCOFD", 
		  "ECEEDERAEWIREATONLVOCSEDF", "EERIWEAREDEECAESCOVLNOTDF", "EERIWEAREDEECNOTAESCOVLFD", "CEEDERAEWIREENLVOCSEATOFD" }, 
		{ "WEATTAC0MAKAT120", "WKAM0CATTAEAT120", "CATTAEWKAM0021TA", "C0MAKWEATTA021TA", 
		  "AM0CATTAEWKAT120", "AKWEATTAC0MAT120", "MAKWEATTAC0021TA", "0CATTAEWKAM021TA" }, 
		{ "YOUNEEMETCAS", "YCTEMEENUOAS", "UOYCTEMEENAS", "UNEEMETCYOAS", 
		  "EMEENUOYCTSA", "ETCYOUNEEMSA", "EMETCYOUNESA", "EENUOYCTEMSA" }, 
		{ "WELOVEPAKSAIDNIYORTISTANIDE", "WITROYINDIASKAPEVOLESTANIDE", "KAPEVOLEWITROYINDIASEDINATS", "KSAIDNIYORTIWELOVEPAEDINATS", 
		  "TROYINDIASKAPEVOLEWISTANIDE", "TIWELOVEPAKSAIDNIYORSTANIDE", "AIDNIYORTIWELOVEPAKSEDINATS", "ASKAPEVOLEWITROYINDIEDINATS" }, 
		{ "JOUBLIERAIJAMAISCETETE", "JOUBLIERAIJAMAISCETETE", "JOUBLIERAIJAMAISCETETE", "JOUBLIERAIJAMAISCETETE", 
		  "ETETECSIAMAJIAREILBUOJ", "ETETECSIAMAJIAREILBUOJ", "ETETECSIAMAJIAREILBUOJ", "ETETECSIAMAJIAREILBUOJ" },
	}

	for i, test := range tests {
		for j, r := range routes {
			c := NewRouteSpiral([]rune(test), NewKeyRoute(widths[i], r))
			testCipher(t, c, expects[i][j], test)
		}
	}
}

func TestRouteSerpent(t *testing.T) {
	widths := [...]int{ 6, 7, 3, 9, 1 }
	routes := [...]route{
		ROUTE_TLR,
		ROUTE_TLD,
		ROUTE_TRL,
		ROUTE_TRD,
		ROUTE_BLR,
		ROUTE_BLU,
		ROUTE_BRL,
		ROUTE_BRU,
	}
	expects := [...][]string{
		{ "WEAREDEVOCSIREDFLECNOTAEE", "WIREEAESEACDTOFOREVLNCEED", "DERAEWISCOVEELFDEREATONCE", "DEECNLVEROFOTDCAESEAEERIW", 
		  "ECNOTAEREDFLEEVOCSIWEARED", "EERIWESEATDCAROFONLVEDEEC", "EEATONCELFDERISCOVEDERAEW", "CEEDEVLNOFORACDTAESEWIREE" }, 
		{ "WEATTAC0021TAKAM", "WKAMAEAT1TT20AC0", "CATTAEWKAT1200MA", "C00AT21TATMAEWKA", 
		  "AM0021TAKWEATTAC", "AKWEAMTAT12TA00C", "MAKAT1200CATTAEW", "0CA02TT1TAEAMAKW" }, 
		{ "YOUNACTSEEME", "YCTEMSAOUNEE", "UOYCANESTEME", "UNEEMSAOYCTE", 
		  "EMEESTCANUOY", "ETCYOASMEENU", "EMETSENACYOU", "EENUOASMETCY" }, 
		{ "WELOVEPAKSEDINATSITROYINDIA", "WITRSELTOYAOVNINIEPDDIEAKSA", "KAPEVOLEWISTANIDESAIDNIYORT", "KSAIEAPDDNIEVNIYAOLTORSEWIT", 
		  "TROYINDIASEDINATSIWELOVEPAK", "TIWESROTLOAYINVEINDDPAEIASK", "AIDNIYORTISTANIDESKAPEVOLEW", "ASKAEIDDPEININVOAYOTLESRTIW" }, 
		{ "JOUBLIERAIJAMAISCETETE", "JOUBLIERAIJAMAISCETETE", "JOUBLIERAIJAMAISCETETE", "JOUBLIERAIJAMAISCETETE", 
		  "ETETECSIAMAJIAREILBUOJ", "ETETECSIAMAJIAREILBUOJ", "ETETECSIAMAJIAREILBUOJ", "ETETECSIAMAJIAREILBUOJ" },
	}

	for i, test := range tests {
		for j, r := range routes {
			c := NewRouteSerpent([]rune(test), NewKeyRoute(widths[i], r))
			testCipher(t, c, expects[i][j], test)
		}
	}
}

func TestMyszkowski(t *testing.T) {
	keys := [...]string{"COBRA", "GIRAFFE", "TETE", "GINGRAYOLVA", "SECRET"}
	expects := [...]string{"EODAEASRENWDVFTEIELORCEEC", "T1C0TA20WKAEAMAT", "OCNSEEYUATEM", "ESEYWOTIIIEANKRLNDATVDAIOPS", "UAITOLRJACEBISEJEMTIAE"}
	expectsPad := [...]string{"^EODAEASRENWDVFTEIELORCEEC$", "^T1.C0.TA20..WKAEAMAT.$", "^OCNSEEYUATEM$", "^ESEY..WOTIIIEANKR.LNDAT.VDAIO.PS.$", "^UAITOLRJACE.BISEJEMTIAE.$"}

	for i, test := range tests {
		key := NewKeyMyszkowski([]rune(keys[i]))
		c := NewMyszkowski([]rune(test), key)
		testCipher(t, c, expects[i], test)
		test2 := ToPadded(test, len([]rune(keys[i])))
		c2 := NewMyszkowski([]rune(test2), key)
		testCipherRegex(t, c2, expectsPad[i], test2)
	}
}

func TestMagnet(t *testing.T) {
	expects := [...]string{"WEECANROETDAIESECLOFVDEER", "WMEAA0T0T2A1CTKA", "YEOMUECEASNT", "WAEILDONVIEYPOARKTISSETDAIN", "JEOTUEBTLEICESRIAAIMJA"}

	for i, test := range tests {
		c := NewMagnet([]rune(test), NewKeyMagnet())
		testCipher(t, c, expects[i], test)
	}
}

func TestElastic(t *testing.T) {
	expects := [...]string{"REEVDOFCLSEIEDAETROANECWE", "KACTA1T2T0A0EAWM", "NTASCEUEOMYE", "NAITDSEISKTARPOEYVIONLDEIWA", "JAIMAARIESICLEBTUEOTJE"}

	for i, test := range tests {
		c := NewElastic([]rune(test), NewKeyElastic())
		testCipher(t, c, expects[i], test)
	}
}

func TestColumnDCount(t *testing.T) {
	keys := [...]string{"CRYPTO", "KATANA", "TOKYO", "BAMBOO", "FOREST"}
	dkeys := [...]string{"SECRET", "DISTURB", "SHRINE", "GRASS", "MOUNTAIN"}
	expects := [...]string{"WCEEOERETRIVFCEODNSELEADA", "A1MATA0WTTAK0EC2", "UONEASEYECTM", "VIEDWOKAONLSNTIEESYIPIRAATD", "URAEJIJSTOEACEMBATLIIE"}

	for i, test := range tests {
		c := NewColumnDCount([]rune(test), NewKeyColumnDCount([]rune(keys[i]), []rune(dkeys[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestColumnDLine(t *testing.T) {
	keys := [...]string{"BIRTHDAY", "MAX", "YEP", "GHOST", "PHILIPPE"}
	expects := [...]string{"IWSCDAOEDEEREEOFTNAVLCREE", "ETK10WATCAT0AMA2", "OCSEAMYUNTEE", "WEOPSDETYILVATSRIAEKAONINDI", "ROIAIEUMSTLEBCEJAJATIE"}
	expectsFill := [...]string{"IWSCDAOEDEEREEOFTNAVLCREE", "EKT10WATT20CAAMA", "OCSMTAEYUNEE", "WEOPSIADLVATEREKASOIINTYNDI", "ROIAIEUMSTLEBCEJAJATIE"}

	for i := range keys {
		c := NewColumnDLine([]rune(tests[i]), NewKeyColumnDLine([]rune(keys[i]), false))
		testCipher(t, c, expects[i], tests[i])
		c2 := NewColumnDLine([]rune(tests[i]), NewKeyColumnDLine([]rune(keys[i]), true))
		testCipher(t, c2, expectsFill[i], tests[i])
	}
}

func TestPolybius(t *testing.T) {
	headers := [...]string{"POWERS", "123456", "HELPUS", "MIAWS", "01835"}
	alphabets := [...]string{
		"HJDI8PZA17E0LYBO23XWV6FQKCGTSRMN5U49",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"MF1BWXNOLIV5EA2UJ0PQZT6KHGDSC73R4Y98",
		"RQZIWSAUHVTPDXGOBKEYCNLMF",
		"EVXGSQDTHZFLAIUMKNOWRCPBY",
	}
	expects := [...]string{
		"EOOROORSORPWPERRROWEEWORRSORPWERWPOROROOREWESOROOR", 
		"45151142421113251142535466661131", 
		"SPEELPUULEEHPPUPLHLHHHLH", 
		"MSWWSAWMISWWAIIIWAMWIMAMIISIMWAAWWIMAMMMWMWSMWSIAAMWII", 
		"83338553818300508883838830888305510018001800",
	}

	for i, test := range tests {
		if len([]rune(headers[i])) < 6 && strings.Contains(test, "J") {
			test = ToJToI(test)
		}
		c := NewPolybius([]rune(test), NewKeyPolybius([]rune(alphabets[i]), []rune(headers[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestADFGX(t *testing.T) {
	keys := [...]string{"CAT", "MEEPOPA", "DISPAS", "HEYTOI", "7273747"}
	alphabets := [...]string{
		"BZQXFVKSEMCYPLNDROHITAUWG",
		"XHCMGOKFVUEBPWYSIZRTQDLAN",
		"EVXGSQDTHZFLAIUMKNOWRCPBY",
		"RQZIWSAUHVTPDXGOBKEYCNLMF",
		"XLTDFAVUYCZRQSKIOWMHENBPG",
	}
	expects := [...]string{
		"GXDGXFFDDGXDGXFFGXGGGGFGAGGAGDDGXDDDDADADGDAFGXAFA", 
		"GFXGGDAFXXGFXDGXGGAXGGAX", 
		"FGAAXXDAXDFAGFXAGFAGXFAA", 
		"XADGDFAXFAGFADFFGFFGFAGAADDXGGFADGXDGXDADGAGGGDDDXGAAA", 
		"AADDAAADGAGGXFXADXAGFFAGAXGDDAFFDAGGDAXAGAXF",
	}

	for i, test := range tests {
		test = ToAlpha(test)
		if strings.Contains(test, "J") {
			test = ToJToI(test)
		}
		c := NewADFGX([]rune(test), NewKeyADFGX([]rune(alphabets[i]), []rune(keys[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestADFGVX(t *testing.T) {
	keys := [...]string{"ALLO", "SALUT", "BONJOUR", "COMMENT", "CAVA"}
	alphabets := [...]string{
		"92DF6VSMBG3I0HZQ17WYRLA5CETPKNX8J4UO",
		"REBSNFZU8DP46CH9XMW1VY32GAKOJL750ITQ",
		"LIGQPV5WFYU913OX8MADBE62ZHSCK7JR0N4T",
		"3U0NBY1PXLVRDWA89GT67F2OJQ5EIZS4KCMH",
		"EO4QB7GFA3Y5HMCJ10P9KN2S8ZVRDW6LXTIU",
	}
	expects := [...]string{
		"GGVDVAGAGVVVVAVDXAXFFGDFXDVGADXVVAVGXVDFFAXDDGDVXA", 
		"AXDVDXXAVFDGFGDVFGFFVVVVXDDXDXXV", 
		"DGVXFXGFAGGGGFGDGGVXFVXG", 
		"FXFAVAAADGVFVXAFVVXAFAVVGVFFADVFGDVAGGGDDFGVGXVGDXGXXF", 
		"GXDAFGDVFGGDVVGVFFXAAAFXXADFFXFXXAAXVXDDGAAA",
	}

	for i, test := range tests {
		c := NewADFGVX([]rune(test), NewKeyADFGVX([]rune(alphabets[i]), []rune(keys[i])))
		testCipher(t, c, expects[i], test)
	}
}

func TestAutokey(t *testing.T) {
	primers := [...]string{"ALLO", "SALUT", "BONJOUR", "COMMENT", "CAVA"}
	alphabets := [...]string{
		"92DF6VSMBG3I0HZQ17WYRLA5CETPKNX8J4UO",
		"REBSNFZU8DP46CH9XMW1VY32GAKOJL750ITQ",
		"LIGQPV5WFYU913OX8MADBE62ZHSCK7JR0N4T",
		"3U0NBY1PXLVRDWA89GT67F2OJQ5EIZS4KCMH",
		"EO4QB7GFA3Y5HMCJ10P9KN2S8ZVRDW6LXTIU",
	}
	expects := [...]string{
		"63MYMP4TH218BCMKVZPEICW3Q", 
		"YKWF0UH9208R3Y2R", 
		"7KWE0WJTTRFQ", 
		"VAPFUSQEOUGIYV1X6J3Q5CBS1VQ", 
		"W3ZHYUULQXJUNGMLRALS5E",
	}

	for i, test := range tests {
		c := NewAutokey([]rune(test), NewKeyAutokey([]rune(alphabets[i]), []rune(primers[i])))
		testCipher(t, c, expects[i], test)
	}
}
