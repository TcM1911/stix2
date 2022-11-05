// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Location represents a geographic location. The location may be described as
// any, some or all of the following: region (e.g., North America), civic
// address (e.g. New York, US), latitude and longitude.
//
// Locations are primarily used to give context to other SDOs. For example, a
// Location could be used in a relationship to describe that the Bourgeois
// Swallow intrusion set originates from Eastern Europe.
//
// The Location SDO can be related to an Identity or Intrusion Set to indicate
// that the identity or intrusion set is located in that location. It can also
// be related from a malware or attack pattern to indicate that they target
// victims in that location. The Location object describes geographic areas,
// not governments, even in cases where that area might have a government. For
// example, a Location representing the United States describes the United
// States as a geographic area, not the federal government of the United
// States.
//
// At least one of the following properties/sets of properties MUST be
// provided:
//	* region
//	* country
//	* latitude and longitude
//
// When a combination of properties is provided (e.g. a region and a latitude
// and longitude) the more precise properties are what the location describes.
// In other words, if a location contains both a region of northern-america and
// a country of us, then the location describes the United States, not all of
// North America. In cases where a latitude and longitude are specified without
// a precision, the location describes the most precise other value.
//
// If precision is specified, then the datum for latitude and longitude MUST be
// WGS 84 [WGS84]. Organizations specifying a designated location using
// latitude and longitude SHOULD specify the precision which is appropriate for
// the scope of the location being identified. The scope is defined by the
// boundary as outlined by the precision around the coordinates.
type Location struct {
	STIXDomainObject
	// Name is used to identify the Location.
	Name string `json:"name,omitempty"`
	// Description is a textual description of the Location.
	Description string `json:"description,omitempty"`
	// Latitude of the Location in decimal degrees. Positive numbers describe
	// latitudes north of the equator, and negative numbers describe latitudes
	// south of the equator. The value of this property MUST be between -90.0
	// and 90.0, inclusive.
	Latitude float64 `json:"latitude,omitempty"`
	// Longitude of the Location in decimal degrees. Positive numbers describe
	// longitudes east of the prime meridian and negative numbers describe
	// longitudes west of the prime meridian. The value of this property MUST
	// be between -180.0 and 180.0, inclusive.
	Longitude float64 `json:"longitude,omitempty"`
	// Precision of the coordinates specified by the latitude and longitude
	// properties. This is measured in meters. The actual Location may be
	// anywhere up to precision meters from the defined point. If this property
	// is not present, then the precision is unspecified. If this property is
	// present, the latitude and longitude properties MUST be present.
	Precision float64 `json:"precision,omitempty"`
	// Region that this Location describes.
	Region string `json:"region,omitempty"`
	// Country  that this Location describes. This property SHOULD contain a
	// valid ISO 3166-1 ALPHA-2 Code.
	Country string `json:"country,omitempty"`
	// AdminstrativeArea is the state, province, or other sub-national
	// administrative area that this Location describes.
	AdministrativeArea string `json:"administrative_area,omitempty"`
	// City that this Location describes.
	City string `json:"city,omitempty"`
	// StreetAddress that this Location describes. This property includes all
	// aspects or parts of the street address. For example, some addresses may
	// have multiple lines including a mailstop or apartment number.
	StreetAddress string `json:"street_address,omitempty"`
	// PostalCode for this Location.
	PostalCode string `json:"postal_code,omitempty"`
}

func (o *Location) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewLocation creates a new Location object.
func NewLocation(region, country string, lat, long float64, opts ...STIXOption) (*Location, error) {
	if region == "" && country == "" && lat == float64(0) && long == float64(0) {
		return nil, ErrPropertyMissing
	}
	// Validate lat and long
	if lat < float64(-90) || lat > float64(90) || long < float64(-180) || long > float64(180) || (lat == float64(0) && long != float64(0)) || (lat != float64(0) && long == float64(0)) {
		return nil, ErrInvalidProperty
	}
	base := newSTIXDomainObject(TypeLocation)
	obj := &Location{
		STIXDomainObject: base,
		Region:           region,
		Country:          country,
		Latitude:         lat,
		Longitude:        long,
	}

	err := applyOptions(obj, opts)
	// Validate precision
	if obj.Precision != float64(0) && (lat == float64(0) || long == float64(0)) {
		return nil, ErrInvalidProperty
	}
	return obj, err
}

const (
	// RegionAfrica is a region identifier for Africa.
	RegionAfrica = "africa"
	// RegionEasternAfrica is a region identifier for Eastern Africa.
	RegionEasternAfrica = "eastern-africa"
	// RegionMiddleAfrica is a region identifier for Middle Africa.
	RegionMiddleAfrica = "middle-africa"
	// RegionNorthernAfrica is a region identifier for Northern Africa.
	RegionNorthernAfrica = "northern-africa"
	// RegionSouthernAfrica is a region identifier for Southern Africa.
	RegionSouthernAfrica = "southern-africa"
	// RegionWesternAfrica is a region identifier for Western Africa.
	RegionWesternAfrica = "western-africa"
	// RegionAmericas is a region identifier for Americas.
	RegionAmericas = "americas"
	// RegionLatinAmericaCaribbean is a region identifier for Latin America and
	// Caribbean.
	RegionLatinAmericaCaribbean = "latin-america-caribbean"
	// RegionSouthAmerica is a region identifier for South America.
	RegionSouthAmerica = "south-america"
	// RegionCaribbean is a region identifier for Caribbean.
	RegionCaribbean = "caribbean"
	// RegionCentralAmerica is a region identifier for Central America.
	RegionCentralAmerica = "central-america"
	// RegionNorthernAmerica is a region identifier for Northern America.
	RegionNorthernAmerica = "northern-america"
	// RegionAsia is a region identifier for Asia.
	RegionAsia = "asia"
	// RegionCentralAsia is a region identifier for Central Asia.
	RegionCentralAsia = "central-asia"
	// RegionEasternAsia is a region identifier for Eastern Asia.
	RegionEasternAsia = "eastern-asia"
	// RegionSouthernAsia is a region identifier for Southern Asia.
	RegionSouthernAsia = "southern-asia"
	// RegionSouthEasternAsia is a region identifier for South Eastern Asia
	RegionSouthEasternAsia = "south-eastern-asia"
	// RegionWesternAsia is a region identifier for Western Asia.
	RegionWesternAsia = "western-asia"
	// RegionEurope is a region identifier for Europe.
	RegionEurope = "europe"
	// RegionEasternEurope is a region identifier for Eastern Europe.
	RegionEasternEurope = "eastern-europe"
	// RegionNorthernEurope is a region identifier for Northern Europe,
	RegionNorthernEurope = "northern-europe"
	// RegionSouthernEurope is a region identifier for Southern Europe.
	RegionSouthernEurope = "southern-europe"
	// RegionWesternEurope is a region identifier for Western Europe.
	RegionWesternEurope = "western-europe"
	// RegionOceania is a region identifier for Oceania.
	RegionOceania = "oceania"
	// RegionAustraliaNewZealand is a region identifier for Australia and New
	// Zealand.
	RegionAustraliaNewZealand = "australia-new-zealand"
	// RegionMelanesia is a region identifier for Melanesia.
	RegionMelanesia = "melanesia"
	// RegionMicronesia is a region identifier for Micronesia.
	RegionMicronesia = "micronesia"
	// RegionPolynesia is a region identifier for Polynesia.
	RegionPolynesia = "polynesia"
	// RegionAntarctica is a region identifier for Antarctica.
	RegionAntarctica = "antarctica"
)
