package saml

import (
	"encoding/xml"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
)

// These tests cover GO-2026-6909 (nil dereferences in assertion validation
// and a namespace-blind Subject.NameID). Every case must return an error or a
// namespace-correct NameID; none may panic.

const (
	govulnIDP = "https://idp.example.test/saml"
	govulnSP  = "https://sp.example.test/metadata"
	govulnACS = "https://sp.example.test/acs"
	govulnReq = "id-request-1"
	govulnNS  = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`
)

type govulnAssertion struct {
	omitSubject bool
	omitSCData  bool
	omitCond    bool
	nameIDs     string
}

func (c govulnAssertion) xml(now time.Time) string {
	ts := now.UTC().Format(time.RFC3339)
	later := now.Add(5 * time.Minute).UTC().Format(time.RFC3339)
	var b strings.Builder
	b.WriteString(`<saml:Assertion ` + govulnNS + ` ID="a1" IssueInstant="` + ts + `" Version="2.0">`)
	b.WriteString(`<saml:Issuer>` + govulnIDP + `</saml:Issuer>`)
	if !c.omitSubject {
		b.WriteString(`<saml:Subject>` + c.nameIDs)
		b.WriteString(`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`)
		if !c.omitSCData {
			b.WriteString(`<saml:SubjectConfirmationData InResponseTo="` + govulnReq + `" NotOnOrAfter="` + later + `" Recipient="` + govulnACS + `"/>`)
		}
		b.WriteString(`</saml:SubjectConfirmation></saml:Subject>`)
	}
	if !c.omitCond {
		b.WriteString(`<saml:Conditions NotBefore="` + ts + `" NotOnOrAfter="` + later + `"><saml:AudienceRestriction><saml:Audience>` + govulnSP + `</saml:Audience></saml:AudienceRestriction></saml:Conditions>`)
	}
	b.WriteString(`</saml:Assertion>`)
	return b.String()
}

func govulnServiceProvider(t *testing.T) *ServiceProvider {
	t.Helper()
	acs, err := url.Parse(govulnACS)
	assert.NilError(t, err)
	meta, err := url.Parse(govulnSP)
	assert.NilError(t, err)
	return &ServiceProvider{
		EntityID:    govulnSP,
		MetadataURL: *meta,
		AcsURL:      *acs,
		IDPMetadata: &EntityDescriptor{EntityID: govulnIDP},
	}
}

func govulnParse(t *testing.T, c govulnAssertion) (*Assertion, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("assertion parsing panicked: %v", r)
		}
	}()
	now := time.Now().UTC()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(c.xml(now)))
	return govulnServiceProvider(t).parseAssertion(doc.Root(), []string{govulnReq}, now, signatureNotRequired)
}

const (
	govulnGoodNameID = `<saml:NameID>alice</saml:NameID>`
	govulnEvilNameID = `<evil:NameID xmlns:evil="urn:evil:ns">admin-victim</evil:NameID>`
)

func TestGO20266909ControlAssertionIsAccepted(t *testing.T) {
	got, err := govulnParse(t, govulnAssertion{nameIDs: govulnGoodNameID})
	assert.NilError(t, err)
	assert.Equal(t, got.Subject.NameID.Value, "alice")
}

func TestGO20266909MissingRequiredElementsAreRejected(t *testing.T) {
	cases := map[string]govulnAssertion{
		"no_subject":                   {omitSubject: true},
		"no_subject_confirmation_data": {nameIDs: govulnGoodNameID, omitSCData: true},
		"no_conditions":                {nameIDs: govulnGoodNameID, omitCond: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := govulnParse(t, c)
			assert.Check(t, err != nil, "expected an error, got assertion %v", got)
		})
	}
}

func TestGO20266909SubjectNameIDIsBoundToAssertionNamespace(t *testing.T) {
	cases := []struct {
		name    string
		nameIDs string
		want    string // "" means no NameID
	}{
		{"foreign_only", govulnEvilNameID, ""},
		{"saml_then_foreign", govulnGoodNameID + govulnEvilNameID, "alice"},
		{"foreign_then_saml", govulnEvilNameID + govulnGoodNameID, "alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := govulnParse(t, govulnAssertion{nameIDs: tc.nameIDs})
			assert.NilError(t, err)
			if tc.want == "" {
				assert.Check(t, got.Subject.NameID == nil, "foreign NameID populated Subject.NameID: %+v", got.Subject.NameID)
				return
			}
			assert.Assert(t, got.Subject.NameID != nil)
			assert.Equal(t, got.Subject.NameID.Value, tc.want)
		})
	}
}

func TestGO20266909OtherNameIDFieldsAreBoundToAssertionNamespace(t *testing.T) {
	const doc = `<saml:SubjectConfirmation ` + govulnNS + ` Method="m">` + govulnEvilNameID + `</saml:SubjectConfirmation>`
	var sc SubjectConfirmation
	assert.NilError(t, xml.Unmarshal([]byte(doc), &sc))
	assert.Check(t, sc.NameID == nil, "foreign NameID populated SubjectConfirmation.NameID")

	const val = `<saml:AttributeValue ` + govulnNS + `>` + govulnEvilNameID + `</saml:AttributeValue>`
	var av AttributeValue
	assert.NilError(t, xml.Unmarshal([]byte(val), &av))
	assert.Check(t, av.NameID == nil, "foreign NameID populated AttributeValue.NameID")
}
