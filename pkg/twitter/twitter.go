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

package twitter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"

	twitter "github.com/fallenstedt/twitter-stream"
	"github.com/fallenstedt/twitter-stream/rules"
	"github.com/fallenstedt/twitter-stream/stream"
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

// Plugin represents our plugin
type Plugin struct {
	plugins.BasePlugin
	FlushInterval uint64   `json:"flushInterval" jsonschema:"description=Flush Interval in milliseconds (Default: 1000)"`
	Rules         []string `json:"rules" jsonschema:"rules for Twitter Stream"`
}

// Info displays information of the plugin to Falco plugin framework
func (plugin *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          6,
		Name:        "twitter",
		Description: "Twitter Stream",
		Contact:     "github.com/falcosecurity/plugins/",
		Version:     "0.2.0",
		EventSource: "twitter",
	}
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (plugin *Plugin) Init(config string) error {
	plugin.FlushInterval = 1000
	return json.Unmarshal([]byte(config), &plugin)
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (plugin *Plugin) Fields() []sdk.FieldEntry {
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
func (plugin *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
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
func (plugin *Plugin) Open(params string) (source.Instance, error) {
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

	presentRules, err := getRules(client)
	if err != nil {
		return nil, err
	}
	deleteRules(client, presentRules)
	addRules(client, plugin.Rules)

	pushEventC := make(chan source.PushEvent)
	tweetsC, err := fetchStream(client)
	if err != nil {
		return nil, err
	}

	go func() {
		for tweet := range tweetsC {
			if tweet.Err != nil {
				client.Stream.StopStream()
				pushEventC <- source.PushEvent{Err: tweet.Err}
				return
			}
			result := tweet.Data.(StreamData)
			result.setAuthorName()

			jsonB, err := json.Marshal(result)
			if err != nil {
				pushEventC <- source.PushEvent{Err: err}
				continue
			}
			pushEventC <- source.PushEvent{Data: jsonB}
		}
	}()

	return source.NewPushInstance(
		pushEventC,
	)
}

func fetchStream(client *twitter.TwitterApi) (<-chan stream.StreamMessage, error) {
	// On Each tweet, decode the bytes into a StreamData struct
	client.Stream.SetUnmarshalHook(func(bytes []byte) (interface{}, error) {
		data := StreamData{}
		err := json.Unmarshal(bytes, &data)
		return data, err
	})

	streamExpansions := twitter.NewStreamQueryParamsBuilder().
		AddExpansion("author_id").
		AddTweetField("created_at").
		AddTweetField("lang").
		Build()

	err := client.Stream.StartStream(streamExpansions)
	if err != nil {
		return nil, err
	}

	return client.Stream.GetMessages(), nil
}

func addRules(client *twitter.TwitterApi, r []string) error {
	if len(r) == 0 {
		return errors.New("no rule to add")
	}

	rules := twitter.NewRuleBuilder()

	for _, i := range r {
		rules.AddRule(i, i) // value, tag
	}

	builtRules := rules.Build()

	res, err := client.Rules.Create(builtRules, false) // dryRun is set to false.
	if err != nil {
		return err
	}

	if res.Errors != nil && len(res.Errors) > 0 {
		return fmt.Errorf("%v: %v", res.Errors[0].Title, res.Errors[0].Value)
	}

	return nil
}

func getRules(client *twitter.TwitterApi) ([]rules.DataRule, error) {
	res, err := client.Rules.Get()
	if err != nil {
		return []rules.DataRule{}, err
	}

	if res.Errors != nil && len(res.Errors) > 0 {
		return []rules.DataRule{}, fmt.Errorf("%v: %v", res.Errors[0].Title, res.Errors[0].Value)
	}

	return res.Data, nil
}

func (s *StreamData) setAuthorName() {
	for _, i := range s.Includes.Users {
		if i.ID == s.Data.AuthorID {
			s.Data.AuthorName = i.Name
			s.Data.AuthorUsername = i.Username
		}
	}
}

func deleteRules(client *twitter.TwitterApi, r []rules.DataRule) error {
	if len(r) == 0 {
		return nil
	}

	ids := []int{}
	for _, i := range r {
		id, _ := strconv.Atoi(i.Id)
		ids = append(ids, id)
	}

	res, err := client.Rules.Delete(rules.NewDeleteRulesRequest(ids...), false)
	if err != nil {
		return err
	}

	if res.Errors != nil && len(res.Errors) > 0 {
		return fmt.Errorf("%v: %v", res.Errors[0].Title, res.Errors[0].Value)
	}

	return nil
}
