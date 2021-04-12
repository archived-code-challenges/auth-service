package models

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// runValidationFunctions is a type-agnostic implementation of the validation function
// runner. It is to be reused by the services.
//
// The value parameter is a pointer to the value being validated and it is passed to each validation
// function. The fns parameter must be a list of validation function wrappers that return their field name
// and the actual validation function. The validation function returned must take value as an input and
// return an error. For example:
//
//		type User struct {
//			...
//		}
//
//		type valFunc func(*User) error
//
//		func validatorWrapper() (string, valFunc) {
//			return "fieldName", func (u *User) error {
//				...
//				return FieldErrorValue
//			}
//		}
//
//		func runValidation(u *User, fns ...func() (string, valFunc)) error {
//			return runValidationFunctions(u, fns)
//		}
//
// This pattern must be followed closely, or this function will panic with obscure errors.
//
// If a validator is not related to a specific field, its wrapper must return an empty string as its field name.
//
// Whan a field validator returns an error, that error is stored in a ValidationError value and no other validators
// for the same field are called.
//
// If a field's validator returns another ValidationError, these will be merged with the resulting field errors
// where the field name will be <validator_field>.<returned_validation_error_field>. If a field's validator returns a
// PublicError implementer, it will simply be included in the resulting ValidationError. Otherwise, the function
// returns immediately with the error returned by the validator.
//
// A non-field validator is only executed if no field errors have been returned by previous validators.
func runValidationFunctions(value interface{}, fns interface{}) error {
	var ve = ValidationError{}

	rfns := reflect.ValueOf(fns)
	for i := 0; i < rfns.Len(); i++ {

		rrets := rfns.Index(i).Call(nil)
		field, rfn := rrets[0].Interface().(string), rrets[1]

		// if it's not a field error
		if field == "" {
			// and no other field errors have been registered yet
			if len(ve) == 0 {
				// then run the non-field validator and return straight away in case of error
				rerr := rfn.Call([]reflect.Value{reflect.ValueOf(value)})
				if err := rerr[0].Interface(); err != nil {
					return err.(error)
				}
			}

			continue
		}

		// else if it is a field validator and no errors yet on this field
		if ve[field] == nil {
			rerr := rfn.Call([]reflect.Value{reflect.ValueOf(value)})

			// run the validation function, if it errors...
			if err := rerr[0].Interface(); err != nil {
				switch terr := err.(type) {
				case ValidationError: // and the error is a ValidationError map, merge the maps
					for k, v := range terr {
						ve[field+"."+k] = v
					}

				case PublicError: // and the error is a PublicError, put it in the ValidationError map
					ve[field] = terr

				default: // otherwise, it's a private error so we should exit
					return terr.(error)
				}
			}
		}
	}

	if len(ve) > 0 {
		return ve
	}

	return nil
}

func NewTestDatabase(t *testing.T) (*gorm.DB, error) {
	var cfg struct {
		Database struct {
			User     string
			Password string
			Name     string
			Port     string
			Host     string
			SSLMode  string
			Timezone string
		}
	}
	cfg.Database.Host = "0.0.0.0"
	cfg.Database.User = "goauthsvc"
	cfg.Database.Password = "secret1234"
	cfg.Database.Name = "goauthsvc"
	cfg.Database.Port = "5432"
	cfg.Database.SSLMode = "disable"
	cfg.Database.Timezone = "Europe/London"

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.Port,
		cfg.Database.SSLMode,
		cfg.Database.Timezone,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err, "opening database connection through dsl")

	return db, nil
}

func CleanupTestDatabase(gdb *gorm.DB) {
	gdb.Exec("DROP SCHEMA public CASCADE")
	gdb.Exec("CREATE SCHEMA public")
	gdb.Migrator().CreateTable(&User{})
}

func CloseDBConnection(gdb *gorm.DB) error {
	sqlDB, err := gdb.DB()
	if err != nil {
		return err
	}
	sqlDB.Close()

	return nil
}

var countryCodes = map[string]string{
	"AF": "Afghanistan",
	"AX": "Åland Islands",
	"AL": "Albania",
	"DZ": "Algeria",
	"AS": "American Samoa",
	"AD": "Andorra",
	"AO": "Angola",
	"AI": "Anguilla",
	"AQ": "Antarctica",
	"AG": "Antigua and Barbuda",
	"AR": "Argentina",
	"AM": "Armenia",
	"AW": "Aruba",
	"AU": "Australia",
	"AT": "Austria",
	"AZ": "Azerbaijan",
	"BH": "Bahrain",
	"BS": "Bahamas",
	"BD": "Bangladesh",
	"BB": "Barbados",
	"BY": "Belarus",
	"BE": "Belgium",
	"BZ": "Belize",
	"BJ": "Benin",
	"BM": "Bermuda",
	"BT": "Bhutan",
	"BO": "Plurinational State of Bolivia",
	"BQ": "Sint Eustatius and Saba Bonaire",
	"BA": "Bosnia and Herzegovina",
	"BW": "Botswana",
	"BV": "Bouvet Island",
	"BR": "Brazil",
	"IO": "British Indian Ocean Territory",
	"BN": "Brunei Darussalam",
	"BG": "Bulgaria",
	"BF": "Burkina Faso",
	"BI": "Burundi",
	"KH": "Cambodia",
	"CM": "Cameroon",
	"CA": "Canada",
	"CV": "Cape Verde",
	"KY": "Cayman Islands",
	"CF": "Central African Republic",
	"TD": "Chad",
	"CL": "Chile",
	"CN": "China",
	"CX": "Christmas Island",
	"CC": "Cocos (Keeling) Islands",
	"CO": "Colombia",
	"KM": "Comoros",
	"CG": "Congo",
	"CD": "the Democratic Republic of the Congo",
	"CK": "Cook Islands",
	"CR": "Costa Rica",
	"CI": "Côte d'Ivoire",
	"HR": "Croatia",
	"CU": "Cuba",
	"CW": "Curaçao",
	"CY": "Cyprus",
	"CZ": "Czech Republic",
	"DK": "Denmark",
	"DJ": "Djibouti",
	"DM": "Dominica",
	"DO": "Dominican Republic",
	"EC": "Ecuador",
	"EG": "Egypt",
	"SV": "El Salvador",
	"GQ": "Equatorial Guinea",
	"ER": "Eritrea",
	"EE": "Estonia",
	"ET": "Ethiopia",
	"FK": "Falkland Islands (Malvinas)",
	"FO": "Faroe Islands",
	"FJ": "Fiji",
	"FI": "Finland",
	"FR": "France",
	"GF": "French Guiana",
	"PF": "French Polynesia",
	"TF": "French Southern Territories",
	"GA": "Gabon",
	"GM": "Gambia",
	"GE": "Georgia",
	"DE": "Germany",
	"GH": "Ghana",
	"GI": "Gibraltar",
	"GR": "Greece",
	"GL": "Greenland",
	"GD": "Grenada",
	"GP": "Guadeloupe",
	"GU": "Guam",
	"GT": "Guatemala",
	"GG": "Guernsey",
	"GN": "Guinea",
	"GW": "Guinea-Bissau",
	"GY": "Guyana",
	"HT": "Haiti",
	"HM": "Heard Island and McDonald Islands",
	"VA": "Holy See (Vatican City State)",
	"HN": "Honduras",
	"HK": "Hong Kong",
	"HU": "Hungary",
	"IS": "Iceland",
	"IN": "India",
	"ID": "Indonesia",
	"IR": "Islamic Republic of Iran",
	"IQ": "Iraq",
	"IE": "Ireland",
	"IM": "Isle of Man",
	"IL": "Israel",
	"IT": "Italy",
	"JM": "Jamaica",
	"JP": "Japan",
	"JE": "Jersey",
	"JO": "Jordan",
	"KZ": "Kazakhstan",
	"KE": "Kenya",
	"KI": "Kiribati",
	"KP": "Democratic People's Republic of Korea",
	"KR": "Republic of Korea",
	"KW": "Kuwait",
	"KG": "Kyrgyzstan",
	"LA": "Lao People's Democratic Republic",
	"LV": "Latvia",
	"LB": "Lebanon",
	"LS": "Lesotho",
	"LR": "Liberia",
	"LY": "Libya",
	"LI": "Liechtenstein",
	"LT": "Lithuania",
	"LU": "Luxembourg",
	"MO": "Macao",
	"MK": "the Former Yugoslav Republic of Macedonia",
	"MG": "Madagascar",
	"MW": "Malawi",
	"MY": "Malaysia",
	"MV": "Maldives",
	"ML": "Mali",
	"MT": "Malta",
	"MH": "Marshall Islands",
	"MQ": "Martinique",
	"MR": "Mauritania",
	"MU": "Mauritius",
	"YT": "Mayotte",
	"MX": "Mexico",
	"FM": "Federated States of Micronesia",
	"MD": "Republic of Moldova",
	"MC": "Monaco",
	"MN": "Mongolia",
	"ME": "Montenegro",
	"MS": "Montserrat",
	"MA": "Morocco",
	"MZ": "Mozambique",
	"MM": "Myanmar",
	"NA": "Namibia",
	"NR": "Nauru",
	"NP": "Nepal",
	"NL": "Netherlands",
	"NC": "New Caledonia",
	"NZ": "New Zealand",
	"NI": "Nicaragua",
	"NE": "Niger",
	"NG": "Nigeria",
	"NU": "Niue",
	"NF": "Norfolk Island",
	"MP": "Northern Mariana Islands",
	"NO": "Norway",
	"OM": "Oman",
	"PK": "Pakistan",
	"PW": "Palau",
	"PS": "State of Palestine",
	"PA": "Panama",
	"PG": "Papua New Guinea",
	"PY": "Paraguay",
	"PE": "Peru",
	"PH": "Philippines",
	"PN": "Pitcairn",
	"PL": "Poland",
	"PT": "Portugal",
	"PR": "Puerto Rico",
	"QA": "Qatar",
	"RE": "Réunion",
	"RO": "Romania",
	"RU": "Russian Federation",
	"RW": "Rwanda",
	"BL": "Saint Barthélemy",
	"SH": "Ascension and Tristan da Cunha Saint Helena",
	"KN": "Saint Kitts and Nevis",
	"LC": "Saint Lucia",
	"MF": "Saint Martin (French part)",
	"PM": "Saint Pierre and Miquelon",
	"VC": "Saint Vincent and the Grenadines",
	"WS": "Samoa",
	"SM": "San Marino",
	"ST": "Sao Tome and Principe",
	"SA": "Saudi Arabia",
	"SN": "Senegal",
	"RS": "Serbia",
	"SC": "Seychelles",
	"SL": "Sierra Leone",
	"SG": "Singapore",
	"SX": "Sint Maarten (Dutch part)",
	"SK": "Slovakia",
	"SI": "Slovenia",
	"SB": "Solomon Islands",
	"SO": "Somalia",
	"ZA": "South Africa",
	"GS": "South Georgia and the South Sandwich Islands",
	"SS": "South Sudan",
	"ES": "Spain",
	"LK": "Sri Lanka",
	"SD": "Sudan",
	"SR": "Suriname",
	"SJ": "Svalbard and Jan Mayen",
	"SZ": "Swaziland",
	"SE": "Sweden",
	"CH": "Switzerland",
	"SY": "Syrian Arab Republic",
	"TW": "Province of China Taiwan",
	"TJ": "Tajikistan",
	"TZ": "United Republic of Tanzania",
	"TH": "Thailand",
	"TL": "Timor-Leste",
	"TG": "Togo",
	"TK": "Tokelau",
	"TO": "Tonga",
	"TT": "Trinidad and Tobago",
	"TN": "Tunisia",
	"TR": "Turkey",
	"TM": "Turkmenistan",
	"TC": "Turks and Caicos Islands",
	"TV": "Tuvalu",
	"UG": "Uganda",
	"UA": "Ukraine",
	"AE": "United Arab Emirates",
	"GB": "United Kingdom",
	"US": "United States",
	"UM": "United States Minor Outlying Islands",
	"UY": "Uruguay",
	"UZ": "Uzbekistan",
	"VU": "Vanuatu",
	"VE": "Bolivarian Republic of Venezuela",
	"VN": "Viet Nam",
	"VG": "British Virgin Islands",
	"VI": "U.S. Virgin Islands",
	"WF": "Wallis and Futuna",
	"EH": "Western Sahara",
	"YE": "Yemen",
	"ZM": "Zambia",
	"ZW": "Zimbabwe",
}
