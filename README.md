# fog-bouncer

![fog-bouncer](https://github.com/dylanegan/fog-bouncer/raw/master/bouncer.jpg)

[![Build Status](https://secure.travis-ci.org/dylanegan/fog-bouncer.png?branch=master)](http://travis-ci.org/dylanegan/fog-bouncer)

A simple way to define and manage security groups for AWS with the backing support from fog.

## Usage

### Installation

```
gem install fog-bouncer
```

### Doorlists

Create a doorlist to manage. Drop it in your project or anywhere on your filesystem. For the following lets assume it is at `/tmp/fog-bouncer.rb`.

```
Fog::Bouncer.security :private do
  account "user", "1234567890"

  group "base", "Base Security Group" do
    source "0.0.0.0/0" do
      icmp 8..0
    end

    source "10.0.0.0/8" do
      tcp 80, 22, 8080..8081
    end
  end

  group "other", "Other Security Group" do
    source "default@user" do
      tcp 22
    end
  end
end
```

### Console

```
➜  ~  export AWS_ACCOUNT_ID=... \
       AWS_ACCESS_KEY_ID=... \
       AWS_SECRET_ACCESS_KEY=...

➜  ~  irb
1.9.3p0 :001 > require 'fog/bouncer'
=> true
1.9.3p0 :002 > doorlist = Fog::Bouncer.load('/tmp/fog-bouncer.rb')
1.9.3p0 :003 > doorlist.import_remote_groups
1.9.3p0 :004 > doorlist.sync
```

### CLI (TBD)

```
➜  ~  export AWS_ACCOUNT_ID=... \
       AWS_ACCESS_KEY_ID=... \
       AWS_SECRET_ACCESS_KEY=...

➜  ~  fog-bouncer sync --list private --file /tmp/fog-bouncer.rb
```

## Environment

* `AWS_ACCOUNT_ID` - your Amazon Web Services account ID
* `AWS_ACCESS_KEY_ID` - your Amazon Web Services access key ID
* `AWS_SECRET_ACCESS_KEY` - your Amazon Web Services secret access key
* `PROVIDER_REGION` - your Amazon Web Services region. Defaults to us-east-1.
