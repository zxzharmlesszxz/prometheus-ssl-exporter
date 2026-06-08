package sslcheck

import "time"

type Snapshot struct {
	AttemptTime                time.Time
	Success                    bool
	Certificates               []Certificate
	Checks                     []CheckStatus
	ChainResults               []ChainResult
	TargetResults              []TargetResult
	Errors                     []CheckError
	ConfiguredCertificateFiles int
	ConfiguredTargets          int
}

type Certificate struct {
	Source              string
	Target              string
	ChainIndex          int
	SubjectCommonName   string
	IssuerCommonName    string
	SerialNumber        string
	NotBefore           time.Time
	NotAfter            time.Time
	TemporarilyValidNow bool
}

type CheckStatus struct {
	Source  string
	Target  string
	Success bool
}

type ChainResult struct {
	Source        string
	Target        string
	ChainVerified bool
}

type TargetResult struct {
	Target        string
	ChainVerified bool
}

type CheckError struct {
	Source string
	Target string
	Err    error
}
