// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Opinion is an assessment of the correctness of the information in a STIX
// Object produced by a different entity. The primary property is the opinion
// property, which captures the level of agreement or disagreement using a
// fixed scale. That fixed scale also supports a numeric mapping to allow for
// consistent statistical operations across opinions.
//
// For example, an analyst from a consuming organization might say that they
// "strongly disagree" with a Campaign object and provide an explanation about
// why. In a more automated workflow, a SOC operator might give an Indicator
// "one star" in their TIP (expressing "strongly disagree") because it is
// considered to be a false positive within their environment. Opinions are
// subjective, and the specification does not address how best to interpret
// them. Sharing communities are encouraged to provide clear guidelines to
// their constituents regarding best practice for the use of Opinion objects
// within the community.
//
// Because Opinions are typically (though not always) created by human analysts
// and are comprised of human-oriented text, they contain an additional
// property to capture the analyst(s) that created the Opinion. This is
// distinct from the CreatedBy property, which is meant to capture the
// organization that created the object.
type Opinion struct {
	STIXDomainObject
	// Explanation is an explanation of why the producer has this Opinion. For
	// example, if an Opinion of strongly-disagree is given, the explanation
	// can contain an explanation of why the Opinion producer disagrees and
	// what evidence they have for their disagreement.
	Explanation string `json:"explanation,omitempty"`
	// Authors is the name of the author(s) of this Opinion (e.g., the
	// analyst(s) that created it).
	Authors []string `json:"authors,omitempty"`
	// Value is the opinion that the producer has about all of the STIX
	// Object(s) listed in the Objects property.
	Value OpinionValue `json:"opinion"`
	// Objects is the STIX Objects that the Opinion is being applied to.
	Objects []Identifier `json:"object_refs"`
}

func (o *Opinion) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewOpinion creates a new Opinion object.
func NewOpinion(val OpinionValue, objects []Identifier, opts ...STIXOption) (*Opinion, error) {
	if len(objects) == 0 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeOpinion)
	obj := &Opinion{
		STIXDomainObject: base,
		Value:            val,
		Objects:          objects,
	}

	err := applyOptions(obj, opts)
	return obj, err
}

// OpinionValue aptures a degree of agreement with the information in a STIX
// Object. It is an ordered enumeration, with the earlier terms representing
// disagreement, the middle term neutral, and the later terms representing
// agreement.
type OpinionValue byte

const (
	// OpinionStronglyDisagree means the creator strongly disagrees with the
	// information and believes it is inaccurate or incorrect.
	OpinionStronglyDisagree OpinionValue = iota + 1
	// OpinionDisagree means the creator disagrees with the information and
	// believes it is inaccurate or incorrect.
	OpinionDisagree
	// OpinionNeutral means the creator is neutral about the accuracy or
	// correctness of the information.
	OpinionNeutral
	// OpinionAgree means the creator agrees with the information and believes
	// that it is accurate and correct.
	OpinionAgree
	// OpinionStronglyAgree means the creator strongly agrees with the
	// information and believes that it is accurate and correct.
	OpinionStronglyAgree
)

var opinionValueMap = map[OpinionValue]string{
	OpinionStronglyDisagree: "strongly-disagree",
	OpinionDisagree:         "disagree",
	OpinionNeutral:          "neutral",
	OpinionAgree:            "agree",
	OpinionStronglyAgree:    "strongly-agree",
}

// String returns the string representation of the OpinionValue.
func (typ OpinionValue) String() string {
	val, ok := opinionValueMap[typ]
	if !ok {
		return ""
	}
	return val
}

// UnmarshalJSON extracts the OpinionValue from the json data.
func (typ *OpinionValue) UnmarshalJSON(b []byte) error {
	t := string(b[1 : len(b)-1])
	for k, v := range opinionValueMap {
		if v == t {
			*typ = k
			return nil
		}
	}
	*typ = OpinionValue(0)
	return nil
}
