// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// tlsSvc is the Certificates page over the certificate store. The earlier
// product-certificate methods (GetTls, CreateCsr, UploadCertificate,
// SetAdminCertificate) stay Not available.
type tlsSvc struct {
	osadminv1connect.UnimplementedTlsServiceHandler
	s *Server
}

func (h *tlsSvc) store() (*certstore.Store, error) {
	if h.s.o.Certs == nil {
		return nil, notAvailable()
	}
	return h.s.o.Certs, nil
}

func (h *tlsSvc) GetCertificateStore(ctx context.Context, _ *connect.Request[osadminv1.GetCertificateStoreRequest]) (*connect.Response[osadminv1.GetCertificateStoreResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	snap, err := st.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := &osadminv1.GetCertificateStoreResponse{Acme: &osadminv1.AcmeState{Available: snap.ACME.Available, Reason: snap.ACME.Reason}, UpdateTrust: h.s.updateTrustWire()}
	for _, c := range snap.Certificates {
		out.Certificates = append(out.Certificates, certProto(c))
	}
	for _, r := range snap.CSRs {
		out.Csrs = append(out.Csrs, csrProto(r))
	}
	for _, e := range snap.Endpoints {
		out.Endpoints = append(out.Endpoints, endpointProto(e))
	}
	return connect.NewResponse(out), nil
}

func (h *tlsSvc) GenerateCsr(ctx context.Context, r *connect.Request[osadminv1.GenerateCsrRequest]) (*connect.Response[osadminv1.GenerateCsrResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	m := r.Msg
	kt, err := keyTypeOf(m.GetKeyType())
	if err != nil {
		return nil, err
	}
	csr, err := st.GenerateCSR(ctx, certstore.CSRRequest{
		Names: m.GetNames(), CommonName: m.GetCommonName(), Organization: m.GetOrganization(), OrganizationalUnit: m.GetOrganizationalUnit(),
		Locality: m.GetLocality(), Province: m.GetProvince(), Country: m.GetCountry(), KeyType: kt,
	})
	callFrom(ctx).noteID(csrName(csr.Names), "csr", csr.ID, "method", "csr", "names", strings.Join(csr.Names, ","), "keyType", csr.KeyType)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.GenerateCsrResponse{Csr: csrProto(csr)}), nil
}

func (h *tlsSvc) CompleteCsr(ctx context.Context, r *connect.Request[osadminv1.CompleteCsrRequest]) (*connect.Response[osadminv1.CompleteCsrResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	c, checks, err := st.CompleteCSR(ctx, r.Msg.GetCsrId(), r.Msg.GetCertificatePem(), r.Msg.GetChainPem(), r.Msg.GetRootPem())
	callFrom(ctx).noteID(certName(c), "certificate", c.ID, append([]string{"method", "csr", "csr", r.Msg.GetCsrId()}, certDetail(c)...)...)
	if err != nil {
		return nil, withReport(err)
	}
	return connect.NewResponse(&osadminv1.CompleteCsrResponse{Certificate: certProto(c), Checks: checksProto(checks)}), nil
}

func (h *tlsSvc) DiscardCsr(ctx context.Context, r *connect.Request[osadminv1.DiscardCsrRequest]) (*connect.Response[osadminv1.DiscardCsrResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	var names []string
	if snap, err := st.Snapshot(ctx); err == nil {
		for _, csr := range snap.CSRs {
			if csr.ID == r.Msg.GetCsrId() {
				names = csr.Names
			}
		}
	}
	callFrom(ctx).noteID(csrName(names), "csr", r.Msg.GetCsrId(), "names", strings.Join(names, ","))
	if err := st.DiscardCSR(r.Msg.GetCsrId()); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.DiscardCsrResponse{}), nil
}

func (h *tlsSvc) ImportCertificate(ctx context.Context, r *connect.Request[osadminv1.ImportCertificateRequest]) (*connect.Response[osadminv1.ImportCertificateResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	m := r.Msg
	format := "pem"
	if len(m.GetPkcs12()) > 0 {
		format = "pkcs12"
	}
	c, checks, err := st.Import(ctx, certstore.ImportRequest{
		CertificatePEM: m.GetCertificatePem(), ChainPEM: m.GetChainPem(), KeyPEM: m.GetKeyPem(),
		PKCS12: m.GetPkcs12(), PKCS12Password: m.GetPkcs12Password(), RootPEM: m.GetRootPem(),
	})
	callFrom(ctx).noteID(certName(c), "certificate", c.ID, append([]string{"method", "upload", "format", format}, certDetail(c)...)...)
	if err != nil {
		return nil, withReport(err)
	}
	return connect.NewResponse(&osadminv1.ImportCertificateResponse{Certificate: certProto(c), Checks: checksProto(checks)}), nil
}

func (h *tlsSvc) DeleteCertificate(ctx context.Context, r *connect.Request[osadminv1.DeleteCertificateRequest]) (*connect.Response[osadminv1.DeleteCertificateResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	// Look the certificate up first, so the entry keeps its names.
	var gone certstore.Certificate
	if snap, err := st.Snapshot(ctx); err == nil {
		for _, c := range snap.Certificates {
			if c.ID == r.Msg.GetCertificateId() {
				gone = c
			}
		}
	}
	callFrom(ctx).noteID(certName(gone), "certificate", r.Msg.GetCertificateId(), certDetail(gone)...)
	if err := st.Delete(r.Msg.GetCertificateId()); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.DeleteCertificateResponse{}), nil
}

func (h *tlsSvc) AssignCertificate(ctx context.Context, r *connect.Request[osadminv1.AssignCertificateRequest]) (*connect.Response[osadminv1.AssignCertificateResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	ep, err := st.Assign(ctx, r.Msg.GetEndpointId(), r.Msg.GetCertificateId())
	h.noteEndpoint(ctx, r.Msg.GetEndpointId(), r.Msg.GetCertificateId(), ep, err)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.AssignCertificateResponse{Endpoint: endpointProto(ep)}), nil
}

func (h *tlsSvc) RevertToSelfSigned(ctx context.Context, r *connect.Request[osadminv1.RevertToSelfSignedRequest]) (*connect.Response[osadminv1.RevertToSelfSignedResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	ep, err := st.Revert(ctx, r.Msg.GetEndpointId())
	h.noteEndpoint(ctx, r.Msg.GetEndpointId(), "", ep, err)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RevertToSelfSignedResponse{Endpoint: endpointProto(ep)}), nil
}

// noteEndpoint records who changed which endpoint to what certificate.
func (h *tlsSvc) noteEndpoint(ctx context.Context, endpoint, id string, ep certstore.Endpoint, err error) {
	detail := []string{"certificate", id}
	if err == nil {
		detail = []string{"certificate", ep.CertificateID, "source", string(ep.Source), "fingerprint", ep.Serving, "expires", ep.Expires.UTC().Format(time.RFC3339)}
		if snap, serr := h.s.o.Certs.Snapshot(ctx); serr == nil {
			for _, c := range snap.Certificates {
				if c.ID == ep.CertificateID {
					detail = append(detail, "source", string(c.Source), "names", strings.Join(sanNames(c), ","))
				}
			}
		}
		h.s.o.Logger.Info("osadmin: :8443 certificate changed", log.F("endpoint", endpoint), log.F("fingerprint", ep.Serving))
	}
	callFrom(ctx).note(endpoint, detail...)
}

func (h *tlsSvc) SetAcme(context.Context, *connect.Request[osadminv1.SetAcmeRequest]) (*connect.Response[osadminv1.SetAcmeResponse], error) {
	return nil, codes.New(codes.TLSACMEUnavailable, "ACME through cert-manager isn't available yet; it comes with the product bundle. Upload a certificate or use a CSR instead")
}

func (h *tlsSvc) RenewNow(context.Context, *connect.Request[osadminv1.RenewNowRequest]) (*connect.Response[osadminv1.RenewNowResponse], error) {
	return nil, codes.New(codes.TLSACMEUnavailable, "nothing renews an assigned certificate; ACME renewal comes with the product bundle")
}

func keyTypeOf(k osadminv1.KeyType) (certstore.KeyType, error) {
	switch k {
	case osadminv1.KeyType_KEY_TYPE_UNSPECIFIED, osadminv1.KeyType_KEY_TYPE_RSA_4096:
		return certstore.KeyRSA4096, nil
	case osadminv1.KeyType_KEY_TYPE_RSA_3072:
		return certstore.KeyRSA3072, nil
	case osadminv1.KeyType_KEY_TYPE_ECDSA_P256:
		return certstore.KeyECDSAP256, nil
	case osadminv1.KeyType_KEY_TYPE_ECDSA_P384:
		return certstore.KeyECDSAP384, nil
	}
	return 0, codes.New(codes.TLSInvalid, "key type: %v isn't one this box makes", k)
}

// described keeps a coded error's chain (for the audit entry) under the
// message the page shows.
type described struct{ err error }

func (d described) Error() string { return codes.Describe(d.err) }
func (d described) Unwrap() error { return d.err }

// withReport turns a refused certificate into its Connect error with every
// check attached as a ValidationReport detail.
func withReport(err error) error {
	var ve *certstore.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	ce := new(connect.Error)
	if !errors.As(toConnect(err), &ce) {
		return err
	}
	out := connect.NewError(ce.Code(), described{err: err})
	if d, derr := connect.NewErrorDetail(&osadminv1.ValidationReport{Checks: checksProto(ve.Checks)}); derr == nil {
		out.AddDetail(d)
	}
	return out
}

// certName is a certificate in words: its names, else its subject.
func certName(c certstore.Certificate) string {
	if n := sanNames(c); len(n) > 0 {
		return "certificate " + strings.Join(n, ", ")
	}
	if c.Leaf != nil && c.Leaf.Subject.CommonName != "" {
		return "certificate " + c.Leaf.Subject.CommonName
	}
	return "certificate"
}

// csrName is a CSR in words: the names it asks for.
func csrName(names []string) string {
	if len(names) == 0 {
		return "CSR"
	}
	return "CSR for " + strings.Join(names, ", ")
}

func certDetail(c certstore.Certificate) []string {
	if c.Leaf == nil {
		return nil
	}
	return []string{"fingerprint", c.Fingerprint, "names", strings.Join(sanNames(c), ","), "expires", c.Leaf.NotAfter.UTC().Format(time.RFC3339)}
}

func sanNames(c certstore.Certificate) []string {
	if c.Leaf == nil {
		return nil
	}
	out := append([]string(nil), c.Leaf.DNSNames...)
	for _, ip := range c.Leaf.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func certProto(c certstore.Certificate) *osadminv1.StoredCertificate {
	if c.Leaf == nil {
		return nil
	}
	out := &osadminv1.StoredCertificate{
		Id: c.ID, Source: certSourceProto(c.Source), Subject: c.Leaf.Subject.String(), Issuer: c.Leaf.Issuer.String(),
		Names: sanNames(c), NotBefore: timestamppb.New(c.Leaf.NotBefore), NotAfter: timestamppb.New(c.Leaf.NotAfter),
		Fingerprint: c.Fingerprint, KeyType: c.KeyType, UsedBy: c.UsedBy, CsrId: c.CSRID, CertificatePem: c.PEM,
	}
	if !c.Added.IsZero() {
		out.Added = timestamppb.New(c.Added)
	}
	for _, x := range c.Chain {
		name := x.Subject.CommonName
		if name == "" {
			name = x.Subject.String()
		}
		out.Chain = append(out.Chain, name)
	}
	return out
}

func certSourceProto(s certstore.Source) osadminv1.CertificateSource {
	switch s {
	case certstore.SourceSelfSigned:
		return osadminv1.CertificateSource_CERTIFICATE_SOURCE_SELF_SIGNED
	case certstore.SourceCSRSigned:
		return osadminv1.CertificateSource_CERTIFICATE_SOURCE_CSR_SIGNED
	case certstore.SourceUploaded:
		return osadminv1.CertificateSource_CERTIFICATE_SOURCE_UPLOADED
	}
	return osadminv1.CertificateSource_CERTIFICATE_SOURCE_UNSPECIFIED
}

func csrProto(r certstore.CSR) *osadminv1.PendingCsr {
	out := &osadminv1.PendingCsr{Id: r.ID, Subject: r.Subject, Names: r.Names, KeyType: r.KeyType, CsrPem: r.PEM}
	if !r.Created.IsZero() {
		out.Created = timestamppb.New(r.Created)
	}
	return out
}

func endpointProto(e certstore.Endpoint) *osadminv1.Endpoint {
	out := &osadminv1.Endpoint{
		Id: e.ID, Name: e.Name, Available: e.Available, UnavailableReason: e.Reason, CertificateId: e.CertificateID,
		Names: e.Names, StateDetail: e.Detail, ServingFingerprint: e.Serving,
	}
	switch e.Source {
	case certstore.EndpointSelfSigned:
		out.Source = osadminv1.EndpointSource_ENDPOINT_SOURCE_SELF_SIGNED
	case certstore.EndpointAssigned:
		out.Source = osadminv1.EndpointSource_ENDPOINT_SOURCE_ASSIGNED
	case certstore.EndpointACME:
		out.Source = osadminv1.EndpointSource_ENDPOINT_SOURCE_ACME
	}
	switch e.State {
	case certstore.StateOK:
		out.State = osadminv1.EndpointState_ENDPOINT_STATE_OK
	case certstore.StateSelfSigned:
		out.State = osadminv1.EndpointState_ENDPOINT_STATE_SELF_SIGNED
	case certstore.StateExpiring:
		out.State = osadminv1.EndpointState_ENDPOINT_STATE_EXPIRING
	case certstore.StateExpired:
		out.State = osadminv1.EndpointState_ENDPOINT_STATE_EXPIRED
	case certstore.StateNames:
		out.State = osadminv1.EndpointState_ENDPOINT_STATE_NAMES_NOT_COVERED
	case certstore.StateUnavailable:
		out.State = osadminv1.EndpointState_ENDPOINT_STATE_UNAVAILABLE
	}
	if !e.Expires.IsZero() {
		out.Expires = timestamppb.New(e.Expires)
	}
	return out
}

func checksProto(cs []certstore.Check) []*osadminv1.ValidationCheck {
	out := make([]*osadminv1.ValidationCheck, 0, len(cs))
	for _, c := range cs {
		out = append(out, &osadminv1.ValidationCheck{Name: c.Name, Passed: c.Passed, Detail: c.Detail})
	}
	return out
}

// tlsWarnings are Status's warnings about :8443's assigned certificate.
func (s *Server) tlsWarnings(ctx context.Context) []*osadminv1.Warning {
	if s.o.Certs == nil {
		return nil
	}
	snap, err := s.o.Certs.Snapshot(ctx)
	if err != nil {
		s.o.Logger.Warn("osadmin: status: the certificate store can't be read", log.F("error", err.Error()))
		return nil
	}
	var out []*osadminv1.Warning
	for _, e := range snap.Endpoints {
		kind := osadminv1.WarningKind_WARNING_KIND_UNSPECIFIED
		switch e.State {
		case certstore.StateExpiring:
			kind = osadminv1.WarningKind_WARNING_KIND_TLS_EXPIRING
		case certstore.StateExpired:
			kind = osadminv1.WarningKind_WARNING_KIND_TLS_EXPIRED
		case certstore.StateNames:
			kind = osadminv1.WarningKind_WARNING_KIND_TLS_NAMES
		}
		if kind != osadminv1.WarningKind_WARNING_KIND_UNSPECIFIED {
			out = append(out, &osadminv1.Warning{Kind: kind, Detail: e.Detail})
		}
	}
	return out
}
