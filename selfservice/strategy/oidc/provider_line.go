// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/ory/herodot"
)

type ProviderLine struct {
	*ProviderGenericOIDC
}

func NewProviderLine(
	config *Configuration,
	reg Dependencies,
) Provider {
	config.IssuerURL = "https://access.line.me"
	return &ProviderLine{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}


func (g *ProviderLine) Claims(ctx context.Context, exchange *oauth2.Token, _ url.Values) (*Claims, error) {
	switch g.config.ClaimsSource {
	case ClaimsSourceIDToken, "":
		return g.claimsFromIDToken(ctx, exchange)
	case ClaimsSourceUserInfo:
		return g.claimsFromUserInfo(ctx, exchange)
	}

	return nil, errors.WithStack(herodot.ErrInternalServerError.
		WithReasonf("Unknown claims source: %q", g.config.ClaimsSource))
}

func (g *ProviderLine) verifyAndDecodeClaimsWithProvider(ctx context.Context, provider *gooidc.Provider, raw string) (*Claims, error) {
	token, err := provider.VerifierContext(g.withHTTPClientContext(ctx), &gooidc.Config{
		ClientID: g.config.ClientID, SupportedSigningAlgs: []string{"HS256", "ES256"}, InsecureSkipSignatureCheck: true}).Verify(ctx, raw)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}

	var claims Claims
	if err := token.Claims(&claims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}

	var rawClaims map[string]interface{}
	if err := token.Claims(&rawClaims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}
	claims.RawClaims = rawClaims

	return &claims, nil
}

func (g *ProviderLine) claimsFromIDToken(ctx context.Context, exchange *oauth2.Token) (*Claims, error) {
	p, raw, err := g.idTokenAndProvider(ctx, exchange)
	if err != nil {
		return nil, err
	}

	return g.verifyAndDecodeClaimsWithProvider(ctx, p, raw)
}

func (g *ProviderLine) idTokenAndProvider(ctx context.Context, exchange *oauth2.Token) (*gooidc.Provider, string, error) {
	raw, ok := exchange.Extra("id_token").(string)
	if !ok || len(raw) == 0 {
		return nil, "", errors.WithStack(ErrIDTokenMissing)
	}

	p, err := g.provider(ctx)
	if err != nil {
		return nil, "", err
	}

	return p, raw, nil
}