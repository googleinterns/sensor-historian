// Copyright 2020 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sensorlogutils is a library of common functions for parsing
// system log for sensor information.
// The feature is only available for Pixel devices with Android version O
// and onwards.
package sensorlogutils

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/googleinterns/sensor-historian/bugreportutils"
	"github.com/googleinterns/sensor-historian/csv"
	"github.com/googleinterns/sensor-historian/historianutils"
	sipb "github.com/googleinterns/sensor-historian/pb/sensorsinfo_proto"
)

var (
	// logEntryRE is a regular expression that matches the common prefix to
	// logcat lines in the bug report.
	// e.g. "11-19 11:29:07.341  2206  2933 233 I"
	// The details part will be matched to individual sensors-hal action events.
	logEntryRE = regexp.MustCompile(`(?P<month>\d+)-(?P<day>\d+)\s*` +
		`(?P<timeStamp>[^.]+)[.](?P<remainder>\d+)\s*` + `(?P<uid>\d+)\s*` +
		`(?P<pid>\d+)\s*` + `(?P<tid>\d+)\s*` + `(?P<entryTag>\S)\s*` +
		`(?P<event>\S+): ` + `(?P<details>.*)`)

	// activateRE is a regular expression that matches the details
	// for sensors-hal log that uses the keyword activate_physical_sensor.
	activateRE = regexp.MustCompile(`activate_physical_sensor:` +
		`(?P<num>\d+),\s*` + `(?P<sensorType>[^\/]+)\/` +
		`(?P<sensorNum>\d+)\s*` + `en=(?P<enabled>\d+)`)

	// batchRE is a regular expression that matches the details
	// for sensors-hal log that uses the keyword batch_physical_sensor.
	batchRE = regexp.MustCompile(`batch_physical_sensor:` + `(?P<num>\d+),\s*` +
		`(?P<sensorType>[^\/]+)\/` + `(?P<sensorNum>\d+)` + `,\s*` +
		`period=(?P<period>\d+),\s*` + `max_latency=(?P<latency>\d+)`)
)

const (
	timeFormat   = "15:04:05"
	sensorsHal   = "sensors-hal"
	completedStr = "completed"
)

type parser struct {
	// referenceYear is the year extracted from the dumpstate line in bugreport.
	// Previous Registration lines don't contain a year in the date string,
	// so we use this to reconstruct the full timestamp.
	referenceYear int

	// referenceMonth is the month extracted from the dumpstate line in bugreport.
	// Since a bugreport may span over a year boundary, we use the month to
	// check whether the year for the event needs to be decremented
	// or incremented.
	referenceMonth int

	// referenceDay is the month extracted from the dumpstate line in bugreport.
	referenceDay int

	// currentTime is the time extracted from the dumpstate line in a bugreport.
	// It is in the traditional HH:MM:SS format.
	referenceTime string

	// earliestTimestampMs is the timestamp corresponding to the last event
	// recorded in the Previous Registration section.
	// If there is no previous registration section, earliestTimestampMs is
	// set to be the timestamp in Ms for the referenceTime.
	earliestTimestampMs int64

	// loc is the location parsed from timezone information in the bugreport.
	// The previous registration is in the user's local timezone
	// which we need to convert to UTC time.
	loc         *time.Location
	buf         *bytes.Buffer
	csvState    *csv.State
	parsingErrs []error

	// sensors is a map from sensor number to the relevant sensor's information.
	sensors map[int32]*sipb.Sensor

	// For all the following maps here, the key is an identifer string
	// made by concatnating the uid, pid, tid, and sensor number information.
	// activation is a map from an identifier string to an event object.
	// The event has an log with keyword activate_physical_sensor
	// and "en=1" shown in the sensors-hal log. The corresponding log marking
	// the action "completed" is not seen.
	activation map[string]*sipb.SubscriptionInfo
	// completedActivation is a map from an identifier string to an event
	// object. The event has an log with keyword activate_physical_sensor
	// and "en=1" shown in the sensors-hal log. Log marking the activation
	// being "completed" is seen.
	completedActivation map[string]*sipb.SubscriptionInfo
	// deactivation is a map from an identifier string to an event object.
	// The event has an log with keyword activate_physical_sensor and "en=0"
	// shown in the sensors-hal log. The corresponding log marking the action
	// "completed" is not seen.
	deactivation map[string]*sipb.SubscriptionInfo
	// completedEvent is a map from an identifier string to a list of
	// event object. Each event in the list has 2 logs with keyword
	// activate_physical_sensor and "en=0" and "en=1" are shown in the two logs.
	// All requests for the envent are completed.
	completedEvent map[string][]*sipb.SubscriptionInfo
}

// Parse is a function that collects information regarding sensor activities
// in the system log section. Specifically, all logs related to the sensors-hal
// event will be looked at.
func Parse(f string, meta *bugreportutils.MetaInfo, sensors map[int32]*sipb.Sensor) []error {
	// Sensor historian only supports andriod sdk version 26 and onwards.
	if meta.SdkVersion < 26 {
		return nil
	}

	loc, err := bugreportutils.TimeZone(f)
	if err != nil {
		errors := []error{fmt.Errorf(
			"Parse Time Zone: missing time zone line in bug report : %s", err)}
		return errors
	}

	// Extract the date and time from the bugreport dumpstate line.
	d, err := bugreportutils.DumpState(f)
	if err != nil {
		errors := []error{fmt.Errorf("Parse Dumpstate: " +
			"could not find dumpstate information in the bugreport")}
		return errors
	}

	buf := new(bytes.Buffer)
	p := &parser{
		referenceYear:       d.Year(),
		referenceMonth:      int(d.Month()),
		referenceDay:        d.Day(),
		referenceTime:       d.Format(timeFormat),
		loc:                 loc,
		buf:                 buf,
		csvState:            csv.NewState(buf, true),
		sensors:             sensors,
		activation:          make(map[string]*sipb.SubscriptionInfo),
		completedActivation: make(map[string]*sipb.SubscriptionInfo),
		deactivation:        make(map[string]*sipb.SubscriptionInfo),
		completedEvent:      make(map[string][]*sipb.SubscriptionInfo),
	}
	errors := []error{}
	for _, line := range strings.Split(f, "\n") {
		m, result := historianutils.SubexpNames(logEntryRE, line)
		if !m {
			continue
		}
		// Only consider the logs for sensorsHal.
		if result["event"] != sensorsHal {
			continue
		}

		timestamp, err := p.fullTimestamp(result["month"], result["day"],
			result["timeStamp"], result["remainder"])
		if err != nil {
			errors = append(errors,
				fmt.Errorf("Error occurs when forming timestamp"))
		}
		if m, details := historianutils.SubexpNames(activateRE, result["details"]); m {
			err = p.processActivationStatement(timestamp, details, result, line)
			errors = append(errors, err)

		} else if m, details := historianutils.SubexpNames(batchRE, result["details"]); m {
			err = p.processBatching(timestamp, details, result, line)
			errors = append(errors, err)
		}
	}
	return errors
}

// getIDInfo is a function that gets uid, pid, tid information from the map
// generated when matching regular expression for the common prefix of
// log-cat line.
func (p parser) getIDInfo(idMap map[string]string) (int32, int32, int32, error) {
	uid, err := strconv.ParseInt(idMap["uid"], 0, 32)
	if err != nil {
		error := fmt.Errorf("Error parsing uid %v:%v", idMap["uid"], err)
		return 0, 0, 0, error
	}
	pid, err := strconv.ParseInt(idMap["pid"], 0, 32)
	if err != nil {
		error := fmt.Errorf("Error parsing pid %v:%v", idMap["pid"], err)
		return 0, 0, 0, error
	}
	tid, err := strconv.ParseInt(idMap["tid"], 0, 32)
	if err != nil {
		error := fmt.Errorf("Error parsing tid %v:%v", idMap["tid"], err)
		return 0, 0, 0, error
	}
	return int32(uid), int32(pid), int32(tid), nil
}

// processActivationStatement is a function that handle all the system logs that contain
// the keyword activate_physical_sensor. It records sensor subscription events
// loged in the system logs.
// TODO: The logic implemented in this function has not been checked.
// More analysis should be done for each case.
func (p parser) processActivationStatement(timestamp int64, detailsMap map[string]string,
	idMap map[string]string, line string) error {
	uid, pid, tid, err := p.getIDInfo(idMap)
	if err != nil {
		error := fmt.Errorf("Error parsing id info for line %v:%v", line, err)
		return error
	}
	n, err := strconv.ParseInt(detailsMap["sensorNum"], 0, 32)
	if err != nil {
		error := fmt.Errorf("Error parsing sensor number %v for line %v:%v",
			detailsMap["sensorNum"], line, err)
		return error
	}
	sensorNum := int32(n)
	sensorType := detailsMap["sensorType"]
	if p.sensors[sensorNum].GetType() != sensorType {
		error := fmt.Errorf("Sensor Type information does not match, "+
			"%v from sensorservice dump, %v from sensors-hal "+
			"for sensor No.%d for line %v:", p.sensors[sensorNum].GetType(),
			sensorType, sensorNum, line)
		return error
	}
	identifier := fmt.Sprintf("%d,%d,%d,%d", uid, pid, tid, sensorNum)

	curEvent := &sipb.SubscriptionInfo{
		SensorNumber: sensorNum,
		UID:          uid,
		Source:       sensorsHal,
	}

	// TODO: create seperate helper functions for handling activation and
	// deactivation. Logic for analysis and grouping events needs to be
	// double checked.
	if detailsMap["enabled"] == "1" {
		// If the line shows en=1, then the sensor is being activated.
		curEvent.StartMs = timestamp
		// If the log does not end with string "completed", the action has not
		// been completed.
		if !strings.HasSuffix(line, completedStr) {
			if activateEvent, exists := p.activation[identifier]; exists {
				error := fmt.Errorf("The activation action has been seen at %v",
					msToTime(activateEvent.GetStartMs()).In(p.loc))
				return error
			} else if activateEvent, exists := p.completedActivation[identifier]; exists {
				error := fmt.Errorf("The activation action has been seen at %v",
					msToTime(activateEvent.GetStartMs()).In(p.loc))
				return error
			}
			p.activation[identifier] = curEvent
		} else {
			if activateEvent, exists := p.completedActivation[identifier]; exists {
				error := fmt.Errorf("The activation action has been seen at %v",
					msToTime(activateEvent.GetStartMs()).In(p.loc))
				return error
			} else if activateEvent, exists := p.activation[identifier]; exists {
				activateEvent.StartMs = timestamp
				p.completedActivation[identifier] = activateEvent
				delete(p.activation, identifier)
			} else {
				p.completedActivation[identifier] = curEvent
			}
		}
	} else if detailsMap["enabled"] == "0" {
		// If it shows en=0, then the sensor is being deactivated.
		curEvent.EndMs = timestamp
		// If the log does not end with string "completed", the action has not
		// been completed.
		if !strings.HasSuffix(line, completedStr) {
			if activateEvent, exists := p.activation[identifier]; exists {
				error := fmt.Errorf("The activation action at %v has not "+
					"been completed",
					msToTime(activateEvent.GetStartMs()).In(p.loc))
				return error
			} else if event, exists := p.completedActivation[identifier]; exists {
				event.EndMs = timestamp
				p.deactivation[identifier] = event
				delete(p.completedActivation, identifier)
			} else {
				p.deactivation[identifier] = curEvent
			}
		} else {
			if event, exists := p.deactivation[identifier]; exists {
				event.EndMs = timestamp
				if allEvents, exists := p.completedEvent[identifier]; exists {
					allEvents = append(allEvents, event)
					p.completedEvent[identifier] = allEvents
					delete(p.deactivation, identifier)
				} else {
					allEvents := []*sipb.SubscriptionInfo{curEvent}
					p.completedEvent[identifier] = allEvents
				}
			} else {
				error := fmt.Errorf("The completed delete action at %v "+
					"has not been seen before",
					msToTime(timestamp).In(p.loc))
				return error
			}
		}
	} else {
		// Log for activate_physical_sensor will include information for en = 1
		// or en=0 for sure
		error := fmt.Errorf("Error parsing enable info %v for line %v:%v",
			detailsMap["enabled"], line, err)
		return error
	}

	return nil
}

// processBatching is a function that handle all the system logs that contain
// the keyword batch_physical_sensor. It records batching information seen
// for subscription events recorded in the system logs.
func (p parser) processBatching(timestamp int64, detailsMap map[string]string,
	idMap map[string]string, line string) error {
	uid, pid, tid, err := p.getIDInfo(idMap)
	if err != nil {
		error := fmt.Errorf("Error parsing id info for line %v:%v", line, err)
		return error
	}
	n, err := strconv.ParseInt(detailsMap["sensorNum"], 0, 32)
	if err != nil {
		error := fmt.Errorf("Error parsing sensor number %v for line %v:%v",
			detailsMap["sensorNum"], line, err)
		return error
	}
	sensorNum := int32(n)
	sensorType := detailsMap["sensorType"]
	if p.sensors[sensorNum].GetType() != sensorType {
		error := fmt.Errorf("Sensor Type information does not match, "+
			"%v from sensorservice dump, %v from sensors-hal "+
			"for sensor No.%d for line %v:", p.sensors[sensorNum].GetType(),
			sensorType, sensorNum, line)
		return error
	}
	identifier := fmt.Sprintf("%d,%d,%d,%d", uid, pid, tid, sensorNum)
	// TODO: the general parsing funcationality has been implemented, need to
	// get the period and latency information and do the analysis.
	// Also update the relevant event information.
	return nil
}

// validMonth checks if a given numbebr represents a valid month.
func validMonth(m int) bool {
	return m >= int(time.January) && m <= int(time.December)
}

// msToTime converts milliseconds since Unix Epoch to a time.Time object.
func msToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond))
}

// fullTimestamp constructs the unix ms timestamp from the given date and time
// information. Since log cat events have no corresponding year, we
// reconstruct the full timestamp using the stored reference year and month
// extracted from the dumpstate line of the bug report.
func (p *parser) fullTimestamp(month, day, partialTimestamp,
	remainder string) (int64, error) {
	parsedMonth, err := strconv.Atoi(month)
	if err != nil {
		return 0, err
	}
	if !validMonth(parsedMonth) {
		return 0, fmt.Errorf("invalid month: %d", parsedMonth)
	}
	year := p.referenceYear
	if int(p.referenceMonth)-parsedMonth < -1 {
		year--
	} else if p.referenceMonth == 12 &&
		time.Month(parsedMonth) == time.January {
		year++
	}
	return bugreportutils.TimeStampToMs(
		fmt.Sprintf("%d-%s-%s %s", year, month, day, partialTimestamp),
		remainder, p.loc)
}
