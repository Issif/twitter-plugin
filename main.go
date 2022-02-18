/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"

	twitter "github.com/fallenstedt/twitter-stream"
	"github.com/fallenstedt/twitter-stream/rules"
)

type StreamData struct {
	Data struct {
		Text           string `json:"text"`
		ID             string `json:"id"`
		AuthorID       string `json:"author_id"`
		AuthorName     string
		AuthorUsername string
		Lang           string    `json:"lang"`
		CreatedAt      time.Time `json:"created_at"`
	} `json:"data"`
	Includes struct {
		Users []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"users"`
	} `json:"includes"`
	MatchingRules []struct {
		ID  string `json:"id"`
		Tag string `json:"tag"`
	} `json:"matching_rules"`
}

// twitterPlugin represents our plugin
type TwitterPlugin struct {
	plugins.BasePlugin
	FlushInterval uint64   `json:"flushInterval" jsonschema:"description=Flush Interval in milliseconds (Default: 1000)"`
	Rules         []string `json:"rules" jsonschema:"rules for Twitter Stream"`
}

// TwitterInstance represents a opened stream based on our Plugin
type TwitterInstance struct {
	source.BaseInstance
	client *twitter.TwitterApi
	msgC   chan StreamData
	errC   chan error
	ctx    context.Context
}

// init function is used for referencing our plugin to the Falco plugin framework
func init() {
	p := &TwitterPlugin{}
	extractor.Register(p)
	source.Register(p)
}

// Info displays information of the plugin to Falco plugin framework
func (twitterPlugin *TwitterPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 6,
		Name:               "twitter",
		Description:        "Twitter Stream",
		Contact:            "github.com/falcosecurity/plugins/",
		Version:            "0.1.0",
		RequiredAPIVersion: "0.3.0",
		EventSource:        "twitter",
	}
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (twitterPlugin *TwitterPlugin) Init(config string) error {
	twitterPlugin.FlushInterval = 1000
	return json.Unmarshal([]byte(config), &twitterPlugin)
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (twitterPlugin *TwitterPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "twitter.text", Desc: "Text of the Tweet"},
		{Type: "string", Name: "twitter.rawtext", Desc: "Text of the Tweet without return lines"},
		{Type: "string", Name: "twitter.authorname", Desc: "Author Name of the Tweet"},
		{Type: "string", Name: "twitter.authorusername", Desc: "Author Username of the Tweet"},
		{Type: "string", Name: "twitter.lang", Desc: "Lang of the Tweet"},
		{Type: "string", Name: "twitter.isrt", Desc: "The Tweet is an RT or not"},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (twitterPlugin *TwitterPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var data StreamData

	rawData, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	err = json.Unmarshal(rawData, &data)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	switch req.Field() {
	case "twitter.text":
		req.SetValue(data.Data.Text)
	case "twitter.rawtext":
		req.SetValue(strings.ReplaceAll(data.Data.Text, "\n", ""))
	case "twitter.authorname":
		req.SetValue(data.Data.AuthorName)
	case "twitter.authorusername":
		req.SetValue(data.Data.AuthorUsername)
	case "twitter.lang":
		req.SetValue(data.Data.Lang)
	case "twitter.isrt":
		req.SetValue(strconv.FormatBool(strings.HasPrefix(data.Data.Text, "RT")))
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (twitterPlugin *TwitterPlugin) Open(params string) (source.Instance, error) {
	apiKey, apiSecret := os.Getenv("TWITTER_API_KEY"), os.Getenv("TWITTER_API_SECRET")
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("env vars TWITTER_API_KEY and TWITTER_API_SECRET must be set")
	}
	tok, err := twitter.NewTokenGenerator().SetApiKeyAndSecret(apiKey, apiSecret).RequestBearerToken()
	if err != nil {
		return nil, err
	}
	client := twitter.NewTwitterStream(tok.AccessToken)
	if err != nil {
		return nil, err
	}

	twitterInstance := &TwitterInstance{
		client: client,
		msgC:   make(chan StreamData),
		errC:   make(chan error),
		ctx:    context.Background(),
	}

	presentRules, err := twitterInstance.getRules()
	if err != nil {
		return nil, err
	}
	twitterInstance.deleteRules(presentRules)
	twitterInstance.addRules(twitterPlugin.Rules)

	go twitterInstance.fetchStream()

	return twitterInstance, nil
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (twitterPlugin *TwitterPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}

// NextBatch is called by Falco plugin framework to get a batch of events from the instance
func (twitterInstance *TwitterInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	twitterPlugin := pState.(*TwitterPlugin)

	i := 0
	expire := time.After(time.Duration(twitterPlugin.FlushInterval) * time.Millisecond)
	for i < evts.Len() {
		select {
		case m := <-twitterInstance.msgC:
			s, _ := json.Marshal(m)
			evt := evts.Get(i)
			if _, err := evt.Writer().Write(s); err != nil {
				return i, err
			}
			i++
		case <-expire:
			// Timeout occurred, flush a partial batch
			return i, sdk.ErrTimeout
		case err := <-twitterInstance.errC:
			// todo: this will cause the program to exit. May we want to ignore some kind of error?
			return i, err
		}
	}

	// The batch is full
	return i, nil
}

func (twitterInstance *TwitterInstance) Close() {
	twitterInstance.ctx.Done()
}

func (twitterInstance *TwitterInstance) addRules(r []string) error {
	if len(r) == 0 {
		return errors.New("no rule to add")
	}

	rules := twitter.NewRuleBuilder()

	for _, i := range r {
		rules.AddRule(i, i) // value, tag
	}

	builtRules := rules.Build()

	res, err := twitterInstance.client.Rules.Create(builtRules, false) // dryRun is set to false.
	if err != nil {
		return err
	}

	if res.Errors != nil && len(res.Errors) > 0 {
		return fmt.Errorf("%v: %v", res.Errors[0].Title, res.Errors[0].Value)
	}

	return nil
}

func (twitterInstance *TwitterInstance) getRules() ([]rules.DataRule, error) {
	res, err := twitterInstance.client.Rules.Get()
	if err != nil {
		return []rules.DataRule{}, err
	}

	if res.Errors != nil && len(res.Errors) > 0 {
		return []rules.DataRule{}, fmt.Errorf("%v: %v", res.Errors[0].Title, res.Errors[0].Value)
	}

	return res.Data, nil
}

func (twitterInstance *TwitterInstance) fetchStream() {
	// On Each tweet, decode the bytes into a StreamData struct
	twitterInstance.client.Stream.SetUnmarshalHook(func(bytes []byte) (interface{}, error) {
		data := StreamData{}
		err := json.Unmarshal(bytes, &data)
		return data, err
	})

	streamExpansions := twitter.NewStreamQueryParamsBuilder().
		AddExpansion("author_id").
		AddTweetField("created_at").
		AddTweetField("lang").
		Build()

	err := twitterInstance.client.Stream.StartStream(streamExpansions)
	if err != nil {
		twitterInstance.errC <- err
		return
	}

	for tweet := range twitterInstance.client.Stream.GetMessages() {
		if tweet.Err != nil {
			twitterInstance.client.Stream.StopStream()
			twitterInstance.errC <- err
			return
		}
		result := tweet.Data.(StreamData)
		result.setAuthorName()

		twitterInstance.msgC <- result
	}
}

func (s *StreamData) setAuthorName() {
	for _, i := range s.Includes.Users {
		if i.ID == s.Data.AuthorID {
			s.Data.AuthorName = i.Name
			s.Data.AuthorUsername = i.Username
		}
	}
}

func (twitterInstance *TwitterInstance) deleteRules(r []rules.DataRule) error {
	if len(r) == 0 {
		return nil
	}

	ids := []int{}
	for _, i := range r {
		id, _ := strconv.Atoi(i.Id)
		ids = append(ids, id)
	}

	res, err := twitterInstance.client.Rules.Delete(rules.NewDeleteRulesRequest(ids...), false)
	if err != nil {
		return err
	}

	if res.Errors != nil && len(res.Errors) > 0 {
		return fmt.Errorf("%v: %v", res.Errors[0].Title, res.Errors[0].Value)
	}

	return nil
}

// main is mandatory but empty, because the plugin will be used as C library by Falco plugin framework
func main() {}
