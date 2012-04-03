# fog-bouncer

![fog-bouncer](https://github.com/dylanegan/fog-bouncer/raw/master/bouncer.jpg)

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

### CLI

```
export AWS_ACCOUNT_ID=... \
       AWS_ACCESS_KEY_ID=... \
       AWS_SECRET_ACCESS_KEY=...

fog-bouncer sync --list private --file /tmp/fog-bouncer.rb
```

## Environment

* `AWS_ACCOUNT_ID` - your Amazon Web Services account ID
* `AWS_ACCESS_KEY_ID` - your Amazon Web Services access key ID
* `AWS_SECRET_ACCESS_KEY` - your Amazon Web Services secret access key
* `PROVIDER_REGION` - your Amazon Web Services region. Defaults to us-east-1.
