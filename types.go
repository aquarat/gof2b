package main

import (
	"github.com/jinzhu/gorm"
	"time"
)

// SystemConfig represents the application's configuration options. Useful for JSON marshaling.
type SystemConfig struct {
	Address, Username, Password, TargetList, ContainerName *string
	EnableReporting *bool
	ReportingInterval *int
	ConfigFile *string
}

// A representation of a "bad" IP. Mostly used for counting. May want to stick this in a database soon...
type BadActor struct {
	gorm.Model
	Count int
	IP string `gorm:"not null;unique"`
	LastSeen time.Time
}

