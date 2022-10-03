# Twitter Plugin

This repository contains the `twittter` plugin for `Falco`, which follows a stream filtered by rules. See [twitter developper guide for details](https://developer.twitter.com/en/docs/twitter-api/tweets/filtered-stream/integrate/build-a-rule).

The plugin also exports fields that extract information from a `twitter` tweet, such as the author name, the lang, the content of the tweet, ...

- [Twitter Plugin](#twitter-plugin)
- [Event Source](#event-source)
- [Supported Fields](#supported-fields)
- [Development](#development)
  - [Requirements](#requirements)
  - [Build](#build)
- [Environment variables](#environment-variables)
- [Settings](#settings)
- [Configurations](#configurations)
- [Usage](#usage)
  - [Requirements](#requirements-1)
  - [Results](#results)

# Event Source

The event source for `twitter` events is `twitter`.

# Supported Fields

| Name                     | Type   | Description                        |
| ------------------------ | ------ | ---------------------------------- |
| `twitter.text`           | string | Text of Tweet                      |
| `twitter.rawtext`        | string | Text of Tweet without return lines |
| `twitter.authorname`     | string | Author Name of the Tweet           |
| `twitter.authorusername` | string | Author Username of the Tweet       |
| `twitter.lang`           | string | Lang of the Tweet                  |
| `twitter.isrt`           | string | `true` if the Tweet is a retweet   |

# Development
## Requirements

You need:
* `Go` >= 1.17

## Build

```shell
make
```

# Environment variables

The plugin needs to authenticate to Twitter API, you need to export:
* `TWITTER_API_KEY`: your API key for Twitter API
* `TWITTER_API_SECRET`: you API Secret Twitter API 

# Settings

Only `init_config` accepts settings:
* `flushinterval`: time en ms between two flushes of events from `twitter` to `Falco` (default: 1000ms)
* `rules`: list of rules for filtering the stream, see [twitter developper guide for details](https://developer.twitter.com/en/docs/twitter-api/tweets/filtered-stream/integrate/build-a-rule)

# Configurations

* `falco.yaml`

  ```yaml
  plugins:
    - name: twitter
      library_path: /etc/falco/audit/libtwitter.so
      init_config:
        rules:
          - cat has:images
          - dog has:images
        flushinterval: 1000
      open_params: ''

  load_plugins: [twitter]

  stdout_output:
    enabled: true
  ```

* `rules/twitter_rules.yaml`

The `source` for rules must be `twitter`.

See example:
```yaml
- rule: New Cat image Tweet
  desc: New Cat image Tweet
  condition: twitter.text contains cat 
  output: "New CAT image tweet from @%twitter.authorname: %twitter.rawtext"
  priority: DEBUG
  source: twitter
  tags: [twitter]
- rule: New Dog image Tweet
  desc: New Dog image Tweet
  condition: twitter.text contains dog 
  output: "New DOG image tweet from @%twitter.authorname: %twitter.rawtext"
  priority: DEBUG
  source: twitter
  tags: [twitter]
```

# Usage

```shell
falco -c falco.yaml -r rules/twitter_rules.yaml
```

## Requirements

* `Falco` >= 0.32

## Results

```shell
14:30:56.334904000: Debug New DOG image tweet from @Kate: Me letting my dog out for a wee #StormEunice https://t.co/f9pfR4jQAe
14:30:57.336734000: Debug New CAT image tweet from @いづも〜アリエナイ〜: めっちゃ見るじゃん。 #チャーリーとチョコレート工場  #猫  #cat #猫のいる暮らし #猫のいる生活 https://t.co/mDBJYyEdb1
14:30:57.337896000: Debug New CAT image tweet from @dimension: dan: RT @heeseungable: jake cat n' dog stuff toy 🐕🐈 ! https://t.co/tV9pBL3xqn
14:30:57.338709000: Debug New CAT image tweet from @imdone: RT @cat_dot_exe: https://t.co/0Fy60CUtYc
14:30:58.339475000: Debug New CAT image tweet from @SAMANTHA CFO: ▶️ ¡ÚLTIMOS DÍAS!🗳 VOTA a SAMANTHA con "Ja no fa mal" en la categoría "Millor cançó de pop-rock". en los premios @enderrock. https://t.co/iB2mQd33BZ https://t.co/s0A772eNe0
14:30:58.340175000: Debug New CAT image tweet from @MawarCrypto: RT @TaylorMusk7: My brother has a cat and I hope his Babycat will grow up soon！Babycat😍 https://t.co/eyQ4VyJ2kR
14:30:59.342610000: Debug New CAT image tweet from @クロネネコ: RT @okirakuoki: おっぴろげ。#cat #ねこ #猫 https://t.co/Kz18EboQ7r
14:30:59.343185000: Debug New CAT image tweet from @Anton: RT @cat_dot_exe: https://t.co/0Fy60CUtYc
```