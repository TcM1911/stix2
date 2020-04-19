package stix2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommonRelationships(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	sdo, err := NewAttackPattern("test")
	require.NoError(err)
	sco, err := NewDomainName("example.com")
	require.NoError(err)

	rel, err := sdo.AddDerivedFrom(sco.ID)
	require.NoError(err)
	assert.Equal(RelationshipTypeDerivedFrom, rel.RelationshipType)
	assert.Equal(sdo.ID, rel.Source)
	assert.Equal(sco.ID, rel.Target)

	rel, err = sdo.AddDuplicateOf(sco.ID)
	require.NoError(err)
	assert.Equal(RelationshipTypeDuplicateOf, rel.RelationshipType)
	assert.Equal(sdo.ID, rel.Source)
	assert.Equal(sco.ID, rel.Target)

	rel, err = sdo.AddRelatedTo(sco.ID)
	require.NoError(err)
	assert.Equal(RelationshipTypeRelatedTo, rel.RelationshipType)
	assert.Equal(sdo.ID, rel.Source)
	assert.Equal(sco.ID, rel.Target)

	rel, err = sco.AddDerivedFrom(sdo.ID)
	require.NoError(err)
	assert.Equal(RelationshipTypeDerivedFrom, rel.RelationshipType)
	assert.Equal(sco.ID, rel.Source)
	assert.Equal(sdo.ID, rel.Target)

	rel, err = sco.AddDuplicateOf(sdo.ID)
	require.NoError(err)
	assert.Equal(RelationshipTypeDuplicateOf, rel.RelationshipType)
	assert.Equal(sco.ID, rel.Source)
	assert.Equal(sdo.ID, rel.Target)

	rel, err = sco.AddRelatedTo(sdo.ID)
	require.NoError(err)
	assert.Equal(RelationshipTypeRelatedTo, rel.RelationshipType)
	assert.Equal(sco.ID, rel.Source)
	assert.Equal(sdo.ID, rel.Target)
}
