package models

// S3Notification is sent when new data is available in S3
type S3Notification struct {
	// S3Bucket is name of the S3 Bucket where data is available
	S3Bucket *string `json:"s3Bucket" validate:"required"`
	// S3ObjectKey is the key of the S3 object that contains the new data
	S3ObjectKey *string `json:"s3ObjectKey" validate:"required"`
	// Events is the number of events in the S3 object
	Events *int `json:"events" validate:"required"`
	// Bytes is the uncompressed size in bytes of the S3 object
	Bytes *int `json:"bytes" validate:"required"`
	// Type is the type of data available in the S3 object (LogData,RuleOutput)
	Type *string `json:"type" validate:"required"`
	// ID is an identified for the data in the S3 object. In case of LogData this will be
	// the Log Type, in case of RuleOutput data this will be the RuleID
	ID *string `json:"id" validate:"required"`
}

const (
	LogData    = "LogData"
	RuleOutput = "RuleOutput"
)

