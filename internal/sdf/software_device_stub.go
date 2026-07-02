//go:build !gmsm

// SDF 软件密码机 stub（无 gmsm 标签时返回错误）。
package sdf

import "errors"

// softwareStub 无 gmsm 标签时的 stub。
type softwareStub struct{}

func newSoftwareDevice() (Device, error) {
	return nil, errors.New("sdf: software device requires -tags gmsm")
}
